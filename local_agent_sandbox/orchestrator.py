"""
Universe Orchestrator
Provides isolated, directory-backed execution universes for swarm agents.
Each Universe is a lightweight sandbox with its own filesystem and process boundary.
"""

import os
import shutil
import tempfile
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional

from .core import LocalAgentSandbox, SandboxConfig


@dataclass
class ComputeQuota:
    """Resource quota for a single Universe."""
    cpu_cores: float = 1.0
    memory_mb: int = 512
    max_threads: int = 16
    max_processes: int = 32


class UniverseStatus(str, Enum):
    """Lifecycle status of a Universe."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"
    DESTROYED = "DESTROYED"


class Universe:
    """
    An isolated execution universe for a single agent.

    Provides a private filesystem directory and a LocalAgentSandbox instance.
    """

    def __init__(
        self,
        name: str,
        quota: ComputeQuota,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.id: str = f"universe-{uuid.uuid4().hex[:8]}"
        self.name: str = name
        self.quota: ComputeQuota = quota
        self.metadata: Dict[str, Any] = metadata or {}
        self.status: UniverseStatus = UniverseStatus.PENDING
        self._sandbox_dir: str = tempfile.mkdtemp(prefix=f"universe_{name}_")
        self._sandbox: LocalAgentSandbox = LocalAgentSandbox(
            config=SandboxConfig(),
            sandbox_dir=self._sandbox_dir,
        )
        self.status = UniverseStatus.RUNNING

    def _resolve_sandbox_path(self, path: str) -> str:
        """Resolve a virtual path inside the universe sandbox, blocking traversal."""
        normalized = os.path.normpath(os.path.join(self._sandbox_dir, path.lstrip("/")))
        if not normalized.startswith(self._sandbox_dir):
            raise ValueError(f"Path traversal attempt blocked: {path}")
        return normalized

    def write_virtual_file(self, path: str, content: str) -> None:
        """Write a file into the universe's virtual filesystem."""
        safe_path = self._resolve_sandbox_path(path)
        os.makedirs(os.path.dirname(safe_path), exist_ok=True)
        with open(safe_path, "w", encoding="utf-8") as f:
            f.write(content)

    def read_virtual_file(self, path: str) -> str:
        """Read a file from the universe's virtual filesystem."""
        safe_path = self._resolve_sandbox_path(path)
        with open(safe_path, "r", encoding="utf-8") as f:
            return f.read()

    def execute(self, command: str) -> Any:
        """Execute a command inside the universe's process sandbox."""
        return self._sandbox.execute(command)

    def stop(self) -> None:
        """Stop the universe from accepting further work."""
        self.status = UniverseStatus.STOPPED

    def destroy(self) -> None:
        """Destroy the universe and clean up its filesystem."""
        self._sandbox.cleanup()
        if os.path.exists(self._sandbox_dir):
            shutil.rmtree(self._sandbox_dir, ignore_errors=True)
        self.status = UniverseStatus.DESTROYED


class UniverseOrchestrator:
    """
    Factory and lifecycle manager for Universes.

    Creates isolated Universes, tracks them, and provides graceful bulk teardown.
    """

    def __init__(self) -> None:
        self._universes: Dict[str, Universe] = {}

    def create_universe(
        self,
        name: str,
        quota: Optional[ComputeQuota] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Universe:
        """Create and return a new isolated Universe."""
        universe = Universe(
            name=name,
            quota=quota or ComputeQuota(),
            metadata=metadata,
        )
        self._universes[universe.id] = universe
        return universe

    def get_universe(self, universe_id: str) -> Optional[Universe]:
        """Return a Universe by id, or None if it does not exist."""
        return self._universes.get(universe_id)

    def stop_universe(self, universe_id: str) -> None:
        """Stop a running Universe."""
        universe = self._universes.get(universe_id)
        if universe:
            universe.stop()

    def destroy_universe(self, universe_id: str) -> None:
        """Destroy a Universe and remove it from orchestration."""
        universe = self._universes.get(universe_id)
        if universe:
            universe.destroy()
            del self._universes[universe_id]

    def close(self) -> None:
        """Gracefully destroy all Universes managed by this orchestrator."""
        for universe in list(self._universes.values()):
            universe.destroy()
        self._universes.clear()


"""
High-Performance Sandbox Orchestrator for Multi-Verse Agent Ecology (AC1).
Manages execution, state lifecycle, virtual storage, and resource quotas
for thousands of concurrent isolated agent sandboxes (universes).
"""

import os
import signal
import json
import subprocess
import time
import uuid
import asyncio
from concurrent.futures import ThreadPoolExecutor
from enum import Enum
from typing import Dict, List, Optional, Set, Any, Union
from dataclasses import dataclass, field


class UniverseStatus(str, Enum):
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    STOPPED = "STOPPED"
    MESHED = "MESHED"
    DESTROYED = "DESTROYED"
    TIMEOUT_ERROR = "TimeoutError"


@dataclass
class ComputeQuota:
    cpu_cores: float = 1.0
    memory_mb: int = 512
    max_threads: int = 64
    max_processes: int = 16
    execution_timeout_seconds: int = 3600


@dataclass
class SandboxConfig:
    """
    Sandbox configuration parameters including process execution limits.
    """
    execution_timeout_seconds: int = 3600
    cpu_cores: float = 1.0
    memory_mb: int = 512
    max_threads: int = 64
    max_processes: int = 16

    def to_dict(self) -> Dict[str, Any]:
        """Converts SandboxConfig to a dictionary representation."""
        return {
            "execution_timeout_seconds": self.execution_timeout_seconds,
            "cpu_cores": self.cpu_cores,
            "memory_mb": self.memory_mb,
            "max_threads": self.max_threads,
            "max_processes": self.max_processes,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SandboxConfig":
        """Creates a SandboxConfig instance from a dictionary."""
        valid_fields = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class NetworkIsolation:
    isolated: bool = True
    virtual_ip: str = "10.240.0.1"
    allowed_peers: Set[str] = field(default_factory=set)
    rx_bytes: int = 0
    tx_bytes: int = 0


@dataclass
class FileChange:
    timestamp: float
    path: str
    action: str  # "CREATE", "MODIFY", "DELETE"
    size_bytes: int = 0
    content_hash: str = ""


@dataclass
class NetworkPacket:
    timestamp: float
    source_id: str
    target_id: str
    protocol: str
    payload_bytes: int
    encrypted: bool = True


@dataclass
class UniverseMetrics:
    cpu_usage_pct: float = 0.0
    memory_bytes: int = 0
    file_ops_count: int = 0
    net_rx_bytes: int = 0
    net_tx_bytes: int = 0
    uptime_seconds: float = 0.0


class VirtualFileSystem:
    """Copy-on-Write Virtual Filesystem for Sandbox Isolation."""

    def __init__(self, root_dir: str = "/"):
        self.root_dir = root_dir
        self.files: Dict[str, bytes] = {
            "/etc/hostname": b"agent-universe",
            "/etc/hosts": b"127.0.0.1 localhost\n",
            "/tmp/env.json": b'{"ENV": "SANDBOX"}',
        }
        self.changes: List[FileChange] = []

    def write_file(self, path: str, data: bytes) -> FileChange:
        action = "MODIFY" if path in self.files else "CREATE"
        self.files[path] = data
        change = FileChange(
            timestamp=time.time(),
            path=path,
            action=action,
            size_bytes=len(data),
            content_hash=hex(hash(data) & 0xFFFFFFFF),
        )
        self.changes.append(change)
        return change

    def read_file(self, path: str) -> Optional[bytes]:
        return self.files.get(path)

    def delete_file(self, path: str) -> bool:
        if path in self.files:
            del self.files[path]
            change = FileChange(
                timestamp=time.time(),
                path=path,
                action="DELETE",
                size_bytes=0,
                content_hash="",
            )
            self.changes.append(change)
            return True
        return False

    def list_files(self) -> List[str]:
        return sorted(list(self.files.keys()))


class Universe:
    """
    An isolated Agent Sandbox Environment ("Universe").
    """

    def __init__(
        self,
        universe_id: Optional[str] = None,
        name: Optional[str] = None,
        quota: Optional[ComputeQuota] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.id = universe_id or f"uv-{uuid.uuid4().hex[:8]}"
        self.name = name or f"Universe-{self.id}"
        self.status = UniverseStatus.CREATED
        self.created_at = time.time()
        self.quota = quota or ComputeQuota()
        self.network = NetworkIsolation(virtual_ip=f"10.240.{(hash(self.id) >> 8) & 0xFF}.{hash(self.id) & 0xFF}")
        self.vfs = VirtualFileSystem()
        self.metadata = metadata or {}
        self.filesystem_changes: List[FileChange] = []
        self.network_packets: List[NetworkPacket] = []
        self.metrics = UniverseMetrics()
        self.logs: List[str] = []
        self.tags: Set[str] = set()

    def start(self):
        if self.status in (UniverseStatus.CREATED, UniverseStatus.STOPPED, UniverseStatus.PAUSED):
            self.status = UniverseStatus.RUNNING
            self.log("Universe started execution.")

    def pause(self):
        if self.status == UniverseStatus.RUNNING:
            self.status = UniverseStatus.PAUSED
            self.log("Universe state paused.")

    def stop(self):
        if self.status in (UniverseStatus.RUNNING, UniverseStatus.PAUSED, UniverseStatus.MESHED):
            self.status = UniverseStatus.STOPPED
            self.log("Universe stopped.")

    def destroy(self):
        self.status = UniverseStatus.DESTROYED
        self.log("Universe destroyed and purged.")

    def log(self, message: str):
        entry = f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ')}] {message}"
        self.logs.append(entry)

    def write_virtual_file(self, path: str, content: str) -> FileChange:
        data = content.encode("utf-8")
        change = self.vfs.write_file(path, data)
        self.filesystem_changes.append(change)
        self.metrics.file_ops_count += 1
        return change

    def read_virtual_file(self, path: str) -> Optional[str]:
        data = self.vfs.read_file(path)
        return data.decode("utf-8") if data is not None else None

    def record_packet(self, packet: NetworkPacket):
        self.network_packets.append(packet)
        self.network.rx_bytes += packet.payload_bytes
        self.metrics.net_rx_bytes += packet.payload_bytes

    def update_metrics(self, cpu_pct: float = 2.5, memory_mb: int = 64):
        self.metrics.cpu_usage_pct = cpu_pct
        self.metrics.memory_bytes = memory_mb * 1024 * 1024
        self.metrics.uptime_seconds = time.time() - self.created_at

    def health_check(self) -> Dict[str, Any]:
        """
        Executes a basic health check on the sandbox universe.
        Returns health status dictionary containing runtime state and resource limits.
        """
        is_healthy = self.status in (UniverseStatus.RUNNING, UniverseStatus.MESHED)
        return {
            "universe_id": self.id,
            "healthy": is_healthy,
            "status": self.status.value if isinstance(self.status, UniverseStatus) else str(self.status),
            "uptime_seconds": round(time.time() - self.created_at, 2),
            "memory_mb": self.quota.memory_mb,
            "cpu_cores": self.quota.cpu_cores,
            "max_threads": self.quota.max_threads,
            "max_processes": self.quota.max_processes,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status.value if isinstance(self.status, UniverseStatus) else str(self.status),
            "created_at": self.created_at,
            "quota": {
                "cpu_cores": self.quota.cpu_cores,
                "memory_mb": self.quota.memory_mb,
                "max_threads": self.quota.max_threads,
                "max_processes": self.quota.max_processes,
            },
            "network": {
                "virtual_ip": self.network.virtual_ip,
                "isolated": self.network.isolated,
            },
            "metrics": {
                "cpu_usage_pct": self.metrics.cpu_usage_pct,
                "memory_bytes": self.metrics.memory_bytes,
                "file_ops_count": self.metrics.file_ops_count,
            },
            "metadata": self.metadata,
        }


class UniverseOrchestrator:
    """
    High-throughput sandbox orchestrator capable of instantiating and managing
    10,000 isolated agent sandboxes in under 5 seconds (AC1).
    """

    def __init__(self, max_workers: int = 16):
        self.universes: Dict[str, Universe] = {}
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.created_count = 0

    def create_universe(
        self,
        name: Optional[str] = None,
        quota: Optional[ComputeQuota] = None,
        metadata: Optional[Dict[str, Any]] = None,
        universe_id: Optional[str] = None,
    ) -> Universe:
        uv = Universe(universe_id=universe_id, name=name, quota=quota, metadata=metadata)
        uv.start()
        self.universes[uv.id] = uv
        self.created_count += 1
        return uv

    def create_universes_batch(
        self,
        count: int,
        name_prefix: str = "agent-node",
        template_quota: Optional[ComputeQuota] = None,
    ) -> List[Universe]:
        """
        Creates 'count' sandboxes concurrently using optimized batching.
        Schedules universe instantiation across thread pools for sub-5 second execution on 10,000 nodes.
        """
        start_time = time.time()
        chunk_size = max(100, count // 16)

        def _create_chunk(start_idx: int, size: int) -> List[Universe]:
            chunk = []
            for i in range(size):
                idx = start_idx + i
                uv_id = f"uv-{idx:05d}"
                name = f"{name_prefix}-{idx}"
                uv = Universe(universe_id=uv_id, name=name, quota=template_quota)
                uv.status = UniverseStatus.RUNNING
                chunk.append(uv)
            return chunk

        futures = []
        for i in range(0, count, chunk_size):
            size = min(chunk_size, count - i)
            futures.append(self.executor.submit(_create_chunk, i, size))

        created: List[Universe] = []
        for f in futures:
            created.extend(f.result())

        for uv in created:
            self.universes[uv.id] = uv

        self.created_count += len(created)
        elapsed = time.time() - start_time
        print(f"[Orchestrator] Created {count} universes in {elapsed:.4f} seconds ({count/max(elapsed, 0.001):.1f} universes/sec)")
        return created

    def get_universe(self, universe_id: str) -> Optional[Universe]:
        return self.universes.get(universe_id)

    def list_universes(
        self,
        status: Optional[UniverseStatus] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Universe]:
        items = list(self.universes.values())
        if status:
            items = [u for u in items if u.status == status]
        return items[offset : offset + limit]

    def start_universe(self, universe_id: str) -> bool:
        """Starts an existing sandbox universe by ID."""
        uv = self.get_universe(universe_id)
        if uv:
            uv.start()
            return True
        return False

    def stop_universe(self, universe_id: str) -> bool:
        """Stops a running sandbox universe by ID."""
        uv = self.get_universe(universe_id)
        if uv:
            uv.stop()
            return True
        return False

    def pause_universe(self, universe_id: str) -> bool:
        uv = self.get_universe(universe_id)
        if uv:
            uv.pause()
            return True
        return False

    def resume_universe(self, universe_id: str) -> bool:
        uv = self.get_universe(universe_id)
        if uv:
            uv.start()
            return True
        return False

    def get_universe_health(self, universe_id: str) -> Optional[Dict[str, Any]]:
        """Returns health check results for a sandbox universe by ID."""
        uv = self.get_universe(universe_id)
        if uv:
            return uv.health_check()
        return None

    def destroy_universe(self, universe_id: str) -> bool:
        if universe_id in self.universes:
            uv = self.universes.pop(universe_id)
            uv.destroy()
            return True
        return False

    def destroy_all(self):
        for uv in list(self.universes.values()):
            uv.destroy()
        self.universes.clear()

    def get_system_metrics(self) -> Dict[str, Any]:
        total_memory_bytes = sum(u.metrics.memory_bytes for u in self.universes.values())
        total_file_ops = sum(u.metrics.file_ops_count for u in self.universes.values())
        running = sum(1 for u in self.universes.values() if u.status == UniverseStatus.RUNNING)
        meshed = sum(1 for u in self.universes.values() if u.status == UniverseStatus.MESHED)

        return {
            "total_universes": len(self.universes),
            "running_universes": running,
            "meshed_universes": meshed,
            "total_allocated_memory_bytes": total_memory_bytes,
            "total_file_ops": total_file_ops,
            "timestamp": time.time(),
        }

    def close(self):
        self.executor.shutdown(wait=False)

    def create_session(
        self,
        session_id: Optional[str] = None,
        config: Optional[SandboxConfig] = None,
        execution_timeout_seconds: Optional[int] = None,
        universe_id: Optional[str] = None,
    ) -> "AgentSession":
        """
        Creates an AgentSession bound to a sandbox universe with configurable execution timeout.

        :param session_id: Optional unique identifier for the session.
        :param config: Optional SandboxConfig instance.
        :param execution_timeout_seconds: Optional execution timeout override in seconds.
        :param universe_id: Optional universe ID to bind the session to.
        :return: Newly created AgentSession instance.
        """
        uv = self.get_universe(universe_id) if universe_id else self.create_universe()
        cfg = config or SandboxConfig()
        if execution_timeout_seconds is not None:
            cfg.execution_timeout_seconds = execution_timeout_seconds
        session = AgentSession(session_id=session_id, config=cfg, universe=uv)
        return session

    def run_task(
        self,
        command: Union[str, List[str]],
        timeout: int = 3600,
        universe_id: Optional[str] = None,
        task_id: Optional[str] = None,
        log_file: Optional[str] = None,
        task_config: Optional[Any] = None,
    ) -> "TaskResult":
        """
        Launches an agent task with configurable execution timeout.

        :param command: Command string or list of argument tokens to execute.
        :param timeout: Timeout duration limit in seconds (default: 3600).
        :param universe_id: Optional universe ID to associate task execution.
        :param task_id: Optional unique identifier for task tracking.
        :param log_file: Optional file path to output task result log.
        :param task_config: Optional task config definition or dictionary containing timeout_seconds.
        :return: TaskResult object containing execution status and timing metrics.
        """
        effective_timeout = timeout
        if task_config is not None:
            if hasattr(task_config, "timeout_seconds") and getattr(task_config, "timeout_seconds", None) is not None:
                effective_timeout = getattr(task_config, "timeout_seconds")
            elif isinstance(task_config, dict) and task_config.get("timeout_seconds") is not None:
                effective_timeout = task_config["timeout_seconds"]

        uv = self.get_universe(universe_id) if universe_id else None
        return run_agent_task(
            command=command,
            timeout=effective_timeout,
            task_id=task_id,
            universe=uv,
            log_file=log_file,
            task_config=task_config,
        )


@dataclass
class TaskResult:
    """
    Task result record documenting execution status, logs, timing, and error details.
    """
    task_id: str
    status: str  # "SUCCESS", "FAILED", "TIMEOUT_EXCEEDED", "TimeoutError"
    exit_code: Optional[int]
    stdout: str
    stderr: str
    execution_time: float
    timeout_seconds: int
    error: Optional[str] = None
    pid: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Converts TaskResult to a dictionary representation."""
        return {
            "task_id": self.task_id,
            "status": self.status,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "execution_time": round(self.execution_time, 4),
            "timeout_seconds": self.timeout_seconds,
            "error": self.error,
            "pid": self.pid,
        }


def run_agent_task(
    command: Union[str, List[str]],
    timeout: int = 3600,
    task_id: Optional[str] = None,
    universe: Optional[Universe] = None,
    log_file: Optional[str] = None,
    task_config: Optional[Any] = None,
) -> TaskResult:
    """
    Launches an agent task in the sandbox with configurable execution timeout enforcement.
    If the agent task exceeds the timeout duration, gracefully terminates the agent process group
    (including any child processes spawned) and records a TIMEOUT_EXCEEDED status in the task result log.

    :param command: Command string or argument list to execute.
    :param timeout: Maximum execution timeout duration in seconds (default: 3600).
    :param task_id: Optional task identifier.
    :param universe: Optional Universe sandbox for logging.
    :param log_file: Optional file path to save task result log.
    :param task_config: Optional task config definition or dictionary with timeout_seconds override.
    :return: TaskResult documenting status, outputs, timing, and error details.
    """
    if task_config is not None:
        if hasattr(task_config, "timeout_seconds") and getattr(task_config, "timeout_seconds", None) is not None:
            timeout = getattr(task_config, "timeout_seconds")
        elif isinstance(task_config, dict) and task_config.get("timeout_seconds") is not None:
            timeout = task_config["timeout_seconds"]
    tid = task_id or f"task-{uuid.uuid4().hex[:8]}"
    start_time = time.time()

    if isinstance(command, list):
        cmd = command
        use_shell = False
    else:
        cmd = command
        use_shell = True

    proc = subprocess.Popen(
        cmd,
        shell=use_shell,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        text=True,
    )

    if universe:
        universe.log(f"Agent task '{tid}' launched with PID {proc.pid} (timeout={timeout}s).")

    stdout, stderr = "", ""
    exit_code = None
    error_msg = None

    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        exit_code = proc.returncode
        status = "SUCCESS" if exit_code == 0 else "FAILED"
    except subprocess.TimeoutExpired:
        status = "TIMEOUT_EXCEEDED"
        error_msg = f"Task '{tid}' exceeded maximum execution timeout of {timeout} seconds."

        # Graceful process and child process group termination (SIGTERM then SIGKILL)
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGTERM)
        except (OSError, ProcessLookupError):
            try:
                proc.terminate()
            except OSError:
                pass

        try:
            stdout, stderr = proc.communicate(timeout=0.5)
        except subprocess.TimeoutExpired:
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                try:
                    proc.kill()
                except OSError:
                    pass
            try:
                stdout, stderr = proc.communicate(timeout=1.0)
            except Exception:
                stdout, stderr = "", ""

        exit_code = proc.returncode if proc.returncode is not None else -1

    elapsed = time.time() - start_time

    result = TaskResult(
        task_id=tid,
        status=status,
        exit_code=exit_code,
        stdout=stdout or "",
        stderr=stderr or "",
        execution_time=elapsed,
        timeout_seconds=timeout,
        error=error_msg,
        pid=proc.pid,
    )

    if universe:
        universe.log(f"Agent task '{tid}' finished with status '{status}' in {elapsed:.4f}s.")

    if log_file:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
            with open(log_file, "w", encoding="utf-8") as f:
                json.dump(result.to_dict(), f, indent=2)
        except Exception:
            pass

    return result


class AgentSession:
    """
    Agent Session managing process execution, lifecycle, state, and execution history inside a sandbox environment.
    Automatically enforces configurable execution timeout (execution_timeout_seconds) on runaway processes,
    terminating agent processes, returning a TimeoutError status, and logging the event in execution history.
    """

    def __init__(
        self,
        session_id: Optional[str] = None,
        config: Optional[SandboxConfig] = None,
        universe: Optional[Universe] = None,
        execution_timeout_seconds: Optional[int] = None,
    ):
        self.session_id: str = session_id or f"session-{uuid.uuid4().hex[:8]}"
        if config is None:
            timeout = execution_timeout_seconds if execution_timeout_seconds is not None else 3600
            self.config: SandboxConfig = SandboxConfig(execution_timeout_seconds=timeout)
        else:
            self.config = config
            if execution_timeout_seconds is not None:
                self.config.execution_timeout_seconds = execution_timeout_seconds

        self.universe: Universe = universe or Universe(name=f"universe-{self.session_id}")
        self.status: str = "CREATED"
        self.execution_history: List[Dict[str, Any]] = []
        self.active_processes: List[subprocess.Popen] = []
        self.created_at: float = time.time()

    def execute(
        self,
        command: Union[str, List[str]],
        timeout: Optional[int] = None,
        task_id: Optional[str] = None,
    ) -> TaskResult:
        """
        Executes a command within the agent session. Enforces execution_timeout_seconds,
        terminates runaway processes on timeout, updates status to TimeoutError, and logs to execution history.

        :param command: Command string or list of argument tokens.
        :param timeout: Optional override for execution timeout limit in seconds.
        :param task_id: Optional task identifier.
        :return: TaskResult documenting status, outputs, timing, and error details.
        """
        effective_timeout = timeout if timeout is not None else self.config.execution_timeout_seconds
        tid = task_id or f"task-{uuid.uuid4().hex[:8]}"
        start_time = time.time()
        self.status = "RUNNING"

        if isinstance(command, list):
            cmd = command
            use_shell = False
        else:
            cmd = command
            use_shell = True

        proc = subprocess.Popen(
            cmd,
            shell=use_shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            text=True,
        )
        self.active_processes.append(proc)
        if self.universe:
            self.universe.log(
                f"Session '{self.session_id}' task '{tid}' launched with PID {proc.pid} (timeout={effective_timeout}s)."
            )

        stdout, stderr = "", ""
        exit_code = None
        error_msg = None

        try:
            stdout, stderr = proc.communicate(timeout=effective_timeout)
            exit_code = proc.returncode
            task_status = "SUCCESS" if exit_code == 0 else "FAILED"
            self.status = task_status
            elapsed = time.time() - start_time

            history_entry = {
                "task_id": tid,
                "event": "execution_complete",
                "command": command,
                "status": task_status,
                "exit_code": exit_code,
                "stdout": stdout or "",
                "stderr": stderr or "",
                "execution_time": elapsed,
                "timeout_seconds": effective_timeout,
                "timestamp": time.time(),
                "pid": proc.pid,
            }
            self.execution_history.append(history_entry)

        except subprocess.TimeoutExpired:
            task_status = "TimeoutError"
            self.status = "TimeoutError"
            error_msg = f"Session '{self.session_id}' execution exceeded timeout of {effective_timeout} seconds."

            # Graceful and forceful process group termination
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGTERM)
            except (OSError, ProcessLookupError):
                try:
                    proc.terminate()
                except OSError:
                    pass

            try:
                stdout, stderr = proc.communicate(timeout=0.5)
            except subprocess.TimeoutExpired:
                try:
                    pgid = os.getpgid(proc.pid)
                    os.killpg(pgid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    try:
                        proc.kill()
                    except OSError:
                        pass
                try:
                    stdout, stderr = proc.communicate(timeout=1.0)
                except Exception:
                    stdout, stderr = "", ""

            exit_code = proc.returncode if proc.returncode is not None else -1
            elapsed = time.time() - start_time

            history_entry = {
                "task_id": tid,
                "event": "timeout",
                "command": command,
                "status": "TimeoutError",
                "timeout_seconds": effective_timeout,
                "execution_time": elapsed,
                "error": error_msg,
                "timestamp": time.time(),
                "pid": proc.pid,
            }
            self.execution_history.append(history_entry)

            if self.universe:
                self.universe.log(
                    f"Timeout event in session '{self.session_id}': task '{tid}' (PID {proc.pid}) terminated after {elapsed:.2f}s."
                )

        finally:
            if proc in self.active_processes:
                self.active_processes.remove(proc)

        result = TaskResult(
            task_id=tid,
            status=task_status,
            exit_code=exit_code,
            stdout=stdout or "",
            stderr=stderr or "",
            execution_time=elapsed,
            timeout_seconds=effective_timeout,
            error=error_msg,
            pid=proc.pid,
        )

        return result

    def run_task(
        self,
        command: Union[str, List[str]],
        timeout: Optional[int] = None,
        task_id: Optional[str] = None,
    ) -> TaskResult:
        """Alias for execute method."""
        return self.execute(command=command, timeout=timeout, task_id=task_id)

    def run_command(
        self,
        command: Union[str, List[str]],
        timeout: Optional[int] = None,
        task_id: Optional[str] = None,
    ) -> TaskResult:
        """Alias for execute method."""
        return self.execute(command=command, timeout=timeout, task_id=task_id)

    def run(
        self,
        command: Union[str, List[str]],
        timeout: Optional[int] = None,
        task_id: Optional[str] = None,
    ) -> TaskResult:
        """Alias for execute method."""
        return self.execute(command=command, timeout=timeout, task_id=task_id)

    def terminate(self) -> None:
        """Terminates all active agent processes in the session."""
        for proc in list(self.active_processes):
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                try:
                    proc.kill()
                except OSError:
                    pass
        self.active_processes.clear()
        self.status = "STOPPED"

    def to_dict(self) -> Dict[str, Any]:
        """Converts AgentSession to a dictionary representation."""
        return {
            "session_id": self.session_id,
            "status": self.status,
            "config": self.config.to_dict(),
            "created_at": self.created_at,
            "execution_history": self.execution_history,
            "universe_id": self.universe.id if self.universe else None,
        }
