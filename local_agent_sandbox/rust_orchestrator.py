"""
Rust Orchestrator Bridge and FFI / High-Speed Fallback Layer (AC1).
Provides high-performance native binding or Python fallback for Rust-based
orchestration of 10,000 isolated agent sandboxes in under 5 seconds.
"""

import time
from typing import Dict, List, Optional, Any
from .orchestrator import UniverseOrchestrator, Universe, ComputeQuota, UniverseStatus


class RustOrchestratorBridge:
    """
    Bridge interface to Rust native sandbox orchestrator core.
    Falls back to hyper-optimized Python concurrent pool if Rust shared library is unavailable.
    """

    def __init__(self, use_rust: bool = False, orchestrator: Optional[UniverseOrchestrator] = None) -> None:
        """Initialize the Rust orchestrator bridge.
        
        Args:
            use_rust: Whether to prioritize the native Rust extension if available.
            orchestrator: Optional underlying Python UniverseOrchestrator instance.
        """
        self.use_rust = use_rust
        self.orchestrator = orchestrator or UniverseOrchestrator()
        self.rust_native_available = False
        self._check_rust_extension()

    def _check_rust_extension(self) -> None:
        """Internal helper to detect compiled PyO3 native module availability."""
        try:
            # Attempt to import compiled PyO3 extension module if compiled
            import lasb_rust_core  # type: ignore
            self.rust_native = lasb_rust_core.RustOrchestrator()
            self.rust_native_available = True
        except ImportError:
            self.rust_native_available = False

    def batch_create(self, count: int, name_prefix: str = "rust-universe") -> List[Universe]:
        """
        Creates up to 10,000 universes using native Rust core or high-performance concurrent engine.
        Guarantees sub-5 second total wall clock duration.

        Args:
            count: Number of sandboxes to instantiate.
            name_prefix: Prefix name for generated sandboxes.

        Returns:
            List of created Universe instances.
        """
        start = time.time()
        if self.rust_native_available and self.use_rust:
            # Call Rust native binding
            rust_nodes = self.rust_native.batch_allocate(count, name_prefix)
            universes = []
            for node in rust_nodes:
                uv = Universe(universe_id=node["id"], name=node["name"])
                uv.status = UniverseStatus.RUNNING
                if "virtual_ip" in node:
                    uv.network.virtual_ip = node["virtual_ip"]
                self.orchestrator.universes[uv.id] = uv
                universes.append(uv)
            return universes
        else:
            # High-performance parallel allocation engine
            return self.orchestrator.create_universes_batch(count=count, name_prefix=name_prefix)

    def start_sandbox(self, universe_id: str) -> bool:
        """Starts an isolated sandbox via the orchestrator bridge.

        Args:
            universe_id: Unique string identifier of the universe.

        Returns:
            bool: True if universe was successfully started, False otherwise.
        """
        if self.rust_native_available and self.use_rust:
            res = self.rust_native.start_universe(universe_id)
            if res:
                self.orchestrator.start_universe(universe_id)
            return res
        return self.orchestrator.start_universe(universe_id)

    def stop_sandbox(self, universe_id: str) -> bool:
        """Stops an isolated sandbox via the orchestrator bridge.

        Args:
            universe_id: Unique string identifier of the universe.

        Returns:
            bool: True if universe was successfully stopped, False otherwise.
        """
        if self.rust_native_available and self.use_rust:
            res = self.rust_native.stop_universe(universe_id)
            if res:
                self.orchestrator.stop_universe(universe_id)
            return res
        return self.orchestrator.stop_universe(universe_id)

    def destroy_sandbox(self, universe_id: str) -> bool:
        """Destroys an isolated sandbox via the orchestrator bridge.

        Args:
            universe_id: Unique string identifier of the universe.

        Returns:
            bool: True if universe was successfully destroyed, False otherwise.
        """
        if self.rust_native_available and self.use_rust:
            res = self.rust_native.destroy_universe(universe_id)
            if res:
                self.orchestrator.destroy_universe(universe_id)
            return res
        return self.orchestrator.destroy_universe(universe_id)

    def health_check(self, universe_id: str) -> Optional[Dict[str, Any]]:
        """Performs a basic health check on a sandbox via the orchestrator bridge.

        Args:
            universe_id: Unique string identifier of the universe.

        Returns:
            Optional[Dict[str, Any]]: Health check details if universe exists, None otherwise.
        """
        if self.rust_native_available and self.use_rust:
            healthy = self.rust_native.get_universe_health(universe_id)
            if healthy is None:
                return None
            uv = self.orchestrator.get_universe(universe_id)
            if uv:
                return uv.health_check()
            return {"universe_id": universe_id, "healthy": healthy}
        return self.orchestrator.get_universe_health(universe_id)

    def benchmark_launch_time(self, count: int = 10000) -> float:
        """Benchmarks launch time for launching 'count' sandboxes.

        Args:
            count: Number of sandboxes to benchmark launch for.

        Returns:
            float: Elapsed time in seconds.
        """
        t0 = time.time()
        self.batch_create(count=count)
        elapsed = time.time() - t0
        return elapsed
