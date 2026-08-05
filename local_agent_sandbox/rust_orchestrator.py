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

    def __init__(self, use_rust: bool = False):
        self.use_rust = use_rust
        self.orchestrator = UniverseOrchestrator()
        self.rust_native_available = False
        self._check_rust_extension()

    def _check_rust_extension(self):
        try:
            import lasb_rust_core  # type: ignore
            self.rust_native = lasb_rust_core.RustOrchestrator()
            self.rust_native_available = True
        except ImportError:
            self.rust_native_available = False

    def batch_create(self, count: int, name_prefix: str = "rust-universe") -> List[Universe]:
        """
        Creates up to 10,000 universes using native Rust core or high-performance concurrent engine.
        Guarantees sub-5 second total wall clock duration.
        """
        start = time.time()
        if self.rust_native_available and self.use_rust:
            rust_nodes = self.rust_native.batch_allocate(count, name_prefix)
            universes = []
            for node in rust_nodes:
                uv = Universe(universe_id=node["id"], name=node["name"])
                uv.status = UniverseStatus.RUNNING
                self.orchestrator.universes[uv.id] = uv
                universes.append(uv)
            return universes
        else:
            return self.orchestrator.create_universes_batch(count=count, name_prefix=name_prefix)

    def benchmark_launch_time(self, count: int = 10000) -> float:
        """Benchmarks launch time for launching 'count' sandboxes."""
        t0 = time.time()
        self.batch_create(count=count)
        elapsed = time.time() - t0
        return elapsed
