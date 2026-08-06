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
