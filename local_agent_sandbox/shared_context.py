"""
Shared Context Virtualization
Thread-safe, localized key-value state manager and vector store that let multiple
virtual agents safely share memory and state without race conditions.
"""

import math
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional

_MISSING = object()


@dataclass
class StateEntry:
    """A single versioned value held in shared state."""

    value: Any
    owner: Optional[str] = None
    version: int = 1
    updated_at: float = field(default_factory=time.time)


class SharedStateStore:
    """Thread-safe, localized key-value store shared across virtual agents.

    Every write is guarded by a reentrant lock and bumps a per-key version and a
    store-wide revision, giving agents race-free shared memory with optimistic
    concurrency primitives such as compare-and-set and get-or-set.
    """

    def __init__(self) -> None:
        self._data: Dict[str, StateEntry] = {}
        self._lock = threading.RLock()
        self._revision = 0

    def set(self, key: str, value: Any, owner: Optional[str] = None) -> int:
        """Store ``value`` under ``key``, returning the new entry version."""
        with self._lock:
            return self._write(key, value, owner)

    def get(self, key: str, default: Any = None) -> Any:
        """Return the value stored under ``key`` or ``default`` when absent."""
        with self._lock:
            entry = self._data.get(key)
            return entry.value if entry is not None else default

    def get_entry(self, key: str) -> Optional[StateEntry]:
        """Return the versioned entry for ``key``, or ``None`` when absent."""
        with self._lock:
            return self._data.get(key)

    def has(self, key: str) -> bool:
        """Return whether ``key`` is present in the shared state."""
        with self._lock:
            return key in self._data

    def compare_and_set(self, key: str, expected: Any, value: Any,
                        owner: Optional[str] = None) -> bool:
        """Atomically set ``key`` to ``value`` only if it currently equals ``expected``.

        Combined with a :meth:`get`, this provides optimistic locking so agents can
        coordinate read-modify-write cycles without losing updates.
        """
        with self._lock:
            entry = self._data.get(key)
            current = entry.value if entry is not None else _MISSING
            if current != expected:
                return False
            self._write(key, value, owner)
            return True

    def get_or_set(self, key: str, default: Any, owner: Optional[str] = None) -> Any:
        """Return the value for ``key``, atomically setting ``default`` when absent."""
        with self._lock:
            entry = self._data.get(key)
            if entry is not None:
                return entry.value
            self._write(key, default, owner)
            return default

    def delete(self, key: str) -> bool:
        """Remove ``key`` from shared state, returning whether it existed."""
        with self._lock:
            if key not in self._data:
                return False
            del self._data[key]
            self._revision += 1
            return True

    def keys(self) -> List[str]:
        """Return a snapshot list of all keys in the shared state."""
        with self._lock:
            return list(self._data.keys())

    def snapshot(self) -> Dict[str, Any]:
        """Return a shallow copy of every key-value pair in shared state."""
        with self._lock:
            return {key: entry.value for key, entry in self._data.items()}

    def size(self) -> int:
        """Return the number of keys currently stored."""
        with self._lock:
            return len(self._data)

    def clear(self) -> int:
        """Remove all keys, returning how many were removed."""
        with self._lock:
            removed = len(self._data)
            self._data.clear()
            self._revision += 1
            return removed

    def stats(self) -> Dict[str, Any]:
        """Return store counters and the current entry count."""
        with self._lock:
            return {"entries": len(self._data), "revision": self._revision}

    def _write(self, key: str, value: Any, owner: Optional[str]) -> int:
        entry = self._data.get(key)
        version = entry.version + 1 if entry is not None else 1
        self._data[key] = StateEntry(value, owner=owner, version=version)
        self._revision += 1
        return version


@dataclass
class VectorEntry:
    """A single stored vector with optional metadata and owner."""

    vector_id: str
    vector: List[float]
    metadata: Dict[str, Any] = field(default_factory=dict)
    owner: Optional[str] = None
    updated_at: float = field(default_factory=time.time)


@dataclass(frozen=True)
class SearchResult:
    """A similarity search hit returned by :class:`SharedVectorStore`."""

    vector_id: str
    score: float
    metadata: Dict[str, Any]
    owner: Optional[str] = None


class SharedVectorStore:
    """Thread-safe, localized vector store with cosine-similarity search.

    Vectors are upserted under unique ids and queried by cosine similarity,
    giving agents a shared, race-free embedding memory for contextual recall.
    """

    def __init__(self, dimensions: Optional[int] = None) -> None:
        if dimensions is not None and dimensions < 1:
            raise ValueError("dimensions must be a positive integer")
        self.dimensions = dimensions
        self._vectors: Dict[str, VectorEntry] = {}
        self._lock = threading.RLock()

    def upsert(self, vector_id: str, vector: List[float],
               metadata: Optional[Dict[str, Any]] = None,
               owner: Optional[str] = None) -> VectorEntry:
        """Insert or replace the vector stored under ``vector_id``."""
        if not vector:
            raise ValueError("vector must not be empty")
        if self.dimensions is not None and len(vector) != self.dimensions:
            raise ValueError(
                f"vector dimension {len(vector)} does not match store dimension "
                f"{self.dimensions}"
            )
        with self._lock:
            entry = VectorEntry(vector_id, list(vector), dict(metadata or {}), owner=owner)
            self._vectors[vector_id] = entry
            return entry

    def get(self, vector_id: str) -> Optional[VectorEntry]:
        """Return the vector entry stored under ``vector_id``, or ``None``."""
        with self._lock:
            return self._vectors.get(vector_id)

    def delete(self, vector_id: str) -> bool:
        """Remove the vector under ``vector_id``, returning whether it existed."""
        with self._lock:
            return self._vectors.pop(vector_id, None) is not None

    def search(self, vector: List[float], top_k: int = 10,
               min_score: float = 0.0) -> List[SearchResult]:
        """Return the ``top_k`` most similar stored vectors by cosine similarity."""
        if not vector:
            raise ValueError("query vector must not be empty")
        if top_k < 1:
            raise ValueError("top_k must be positive")
        with self._lock:
            results = []
            for entry in self._vectors.values():
                score = self._cosine(vector, entry.vector)
                if score >= min_score:
                    results.append(
                        SearchResult(
                            vector_id=entry.vector_id,
                            score=score,
                            metadata=dict(entry.metadata),
                            owner=entry.owner,
                        )
                    )
            results.sort(key=lambda result: result.score, reverse=True)
            return results[:top_k]

    def count(self) -> int:
        """Return the number of stored vectors."""
        with self._lock:
            return len(self._vectors)

    def snapshot(self) -> Dict[str, VectorEntry]:
        """Return a shallow copy of every stored vector entry."""
        with self._lock:
            return {vector_id: entry for vector_id, entry in self._vectors.items()}

    def clear(self) -> int:
        """Remove all vectors, returning how many were removed."""
        with self._lock:
            removed = len(self._vectors)
            self._vectors.clear()
            return removed

    def stats(self) -> Dict[str, Any]:
        """Return store counters and the current vector count."""
        with self._lock:
            return {"vectors": len(self._vectors), "dimensions": self.dimensions}

    @staticmethod
    def _cosine(left: List[float], right: List[float]) -> float:
        dot = 0.0
        left_norm = 0.0
        right_norm = 0.0
        for x, y in zip(left, right):
            dot += x * y
            left_norm += x * x
            right_norm += y * y
        denom = math.sqrt(left_norm) * math.sqrt(right_norm)
        if denom == 0.0:
            return 0.0
        return dot / denom


class SharedContext:
    """Virtualized shared memory for a swarm of virtual agents.

    Composes a thread-safe key-value :class:`SharedStateStore` with a thread-safe
    :class:`SharedVectorStore` so every agent in a swarm reads and writes the same
    memory and state without race conditions.
    """

    def __init__(self, state_store: Optional[SharedStateStore] = None,
                 vector_store: Optional[SharedVectorStore] = None) -> None:
        self.state = state_store or SharedStateStore()
        self.vectors = vector_store or SharedVectorStore()
        self._lock = threading.RLock()

    @contextmanager
    def locked(self) -> Iterator["SharedContext"]:
        """Acquire the shared context lock for compound multi-store operations."""
        with self._lock:
            yield self

    def remember(self, key: str, value: Any, owner: Optional[str] = None) -> int:
        """Store ``value`` into shared state under ``key``."""
        return self.state.set(key, value, owner)

    def recall(self, key: str, default: Any = None) -> Any:
        """Return the shared-state value stored under ``key``."""
        return self.state.get(key, default)

    def forget(self, key: str) -> bool:
        """Remove ``key`` from shared state, returning whether it existed."""
        return self.state.delete(key)

    def store_vector(self, vector_id: str, vector: List[float],
                     metadata: Optional[Dict[str, Any]] = None,
                     owner: Optional[str] = None) -> VectorEntry:
        """Upsert ``vector`` into the shared vector store under ``vector_id``."""
        return self.vectors.upsert(vector_id, vector, metadata, owner)

    def query_vector(self, vector: List[float], top_k: int = 10,
                     min_score: float = 0.0) -> List[SearchResult]:
        """Search the shared vector store for the closest vectors."""
        return self.vectors.search(vector, top_k=top_k, min_score=min_score)

    def snapshot(self) -> Dict[str, Any]:
        """Return a snapshot of the full shared state and vector stores."""
        return {"state": self.state.snapshot(), "vectors": self.vectors.snapshot()}

    def stats(self) -> Dict[str, Any]:
        """Return aggregate stats for both underlying stores."""
        return {"state": self.state.stats(), "vectors": self.vectors.stats()}

    def reset(self) -> Dict[str, int]:
        """Clear both stores, returning how many entries were removed."""
        with self._lock:
            return {"state": self.state.clear(), "vectors": self.vectors.clear()}
