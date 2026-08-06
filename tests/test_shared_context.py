import threading

import pytest

from local_agent_sandbox.shared_context import (
    SharedContext,
    SharedStateStore,
    SharedVectorStore,
    SearchResult,
    VectorEntry,
)
from local_agent_sandbox.tdl import AgentConfig, SwarmLifecycleManager, TDLTopology


def test_state_store_set_get_delete():
    """Shared state supports basic set, get, has, and delete operations."""
    store = SharedStateStore()
    assert store.set("goal", "ship it", owner="alpha") == 1
    assert store.get("goal") == "ship it"
    assert store.has("goal")
    assert store.delete("goal") is True
    assert store.delete("goal") is False
    assert store.get("goal", "missing") == "missing"
    assert store.has("goal") is False


def test_state_store_versioning_and_revision():
    """Writes bump per-key versions and the store-wide revision counter."""
    store = SharedStateStore()
    assert store.set("counter", 0) == 1
    assert store.set("counter", 1) == 2
    assert store.set("counter", 2) == 3
    assert store.get_entry("counter").version == 3
    assert store.stats()["revision"] == 3
    assert store.stats()["entries"] == 1


def test_compare_and_set_semantics():
    """compare_and_set only applies when the current value matches expected."""
    store = SharedStateStore()
    store.set("x", 1)

    assert store.compare_and_set("x", 1, 2) is True
    assert store.get("x") == 2
    assert store.compare_and_set("x", 1, 3) is False
    assert store.get("x") == 2

    # Absent keys never match an expected value.
    assert store.compare_and_set("absent", None, "value") is False
    assert store.has("absent") is False


def test_get_or_set_is_atomic():
    """get_or_set returns the existing value and only writes when absent."""
    store = SharedStateStore()
    assert store.get_or_set("mode", "fast") == "fast"
    assert store.get_or_set("mode", "slow") == "fast"
    assert store.get("mode") == "fast"


def test_state_store_snapshot_and_clear():
    """Snapshots reflect the state and clear removes every entry."""
    store = SharedStateStore()
    store.set("a", 1)
    store.set("b", 2)
    assert store.snapshot() == {"a": 1, "b": 2}
    assert sorted(store.keys()) == ["a", "b"]
    assert store.size() == 2

    assert store.clear() == 2
    assert store.size() == 0
    assert store.snapshot() == {}


def test_concurrent_writes_do_not_lose_keys():
    """Many threads writing distinct keys leave every key intact."""
    store = SharedStateStore()
    workers = 8
    per_worker = 100
    barrier = threading.Barrier(workers)

    def worker(worker_id: int) -> None:
        barrier.wait()
        for i in range(per_worker):
            store.set(f"k:{worker_id}:{i}", i)

    threads = [threading.Thread(target=worker, args=(w,)) for w in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert store.size() == workers * per_worker
    assert store.get("k:7:99") == 99


def test_compare_and_set_prevents_lost_updates():
    """Concurrent incrementing via compare-and-set loses no updates."""
    store = SharedStateStore()
    store.set("counter", 0)
    workers = 8
    increments = 100
    barrier = threading.Barrier(workers)

    def worker() -> None:
        barrier.wait()
        for _ in range(increments):
            while True:
                current = store.get("counter")
                if store.compare_and_set("counter", current, current + 1):
                    break

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert store.get("counter") == workers * increments


def test_vector_store_upsert_get_delete():
    """Vector store supports upsert, get, delete, and count."""
    store = SharedVectorStore()
    entry = store.upsert("m1", [1.0, 0.0], metadata={"task": "search"}, owner="alpha")
    assert isinstance(entry, VectorEntry)
    assert store.get("m1") is entry
    assert store.count() == 1

    # Upsert replaces in place without growing the store.
    store.upsert("m1", [0.0, 1.0])
    assert store.get("m1").vector == [0.0, 1.0]
    assert store.count() == 1

    assert store.delete("m1") is True
    assert store.delete("m1") is False
    assert store.get("m1") is None
    assert store.count() == 0


def test_vector_search_returns_closest():
    """Search ranks stored vectors by cosine similarity."""
    store = SharedVectorStore()
    store.upsert("a", [1.0, 0.0])
    store.upsert("b", [0.0, 1.0])
    store.upsert("c", [1.0, 1.0])

    results = store.search([1.0, 0.0])
    assert [r.vector_id for r in results] == ["a", "c", "b"]
    assert isinstance(results[0], SearchResult)
    assert results[0].score == pytest.approx(1.0)
    assert results[1].score == pytest.approx(1 / 2 ** 0.5)
    assert results[0].score > results[1].score > results[2].score


def test_vector_search_top_k_and_min_score():
    """Search honors top_k and min_score filters."""
    store = SharedVectorStore()
    store.upsert("a", [1.0, 0.0])
    store.upsert("b", [0.0, 1.0])

    assert [r.vector_id for r in store.search([1.0, 0.0], top_k=1)] == ["a"]
    assert [r.vector_id for r in store.search([1.0, 0.0], min_score=0.8)] == ["a"]
    assert [r.vector_id for r in store.search([1.0, 0.0], min_score=0.99)] == ["a"]
    assert store.search([1.0, 0.0], min_score=1.5) == []


def test_vector_store_dimension_validation():
    """Upserts must match the store dimensions and be non-empty."""
    store = SharedVectorStore(dimensions=3)
    with pytest.raises(ValueError):
        store.upsert("x", [1.0, 2.0])
    with pytest.raises(ValueError):
        store.upsert("y", [])

    no_dims = SharedVectorStore()
    with pytest.raises(ValueError):
        no_dims.upsert("z", [])


def test_concurrent_vector_upserts_are_race_free():
    """Concurrent upserts all land without losing entries."""
    store = SharedVectorStore()
    workers = 8
    per_worker = 50
    barrier = threading.Barrier(workers)

    def worker(worker_id: int) -> None:
        barrier.wait()
        for i in range(per_worker):
            store.upsert(f"v:{worker_id}:{i}", [float(worker_id), float(i)])

    threads = [threading.Thread(target=worker, args=(w,)) for w in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert store.count() == workers * per_worker
    assert store.get("v:7:49").vector == [7.0, 49.0]
    assert len(store.search([1.0, 0.0], top_k=workers)) == workers


def test_shared_context_remember_recall_and_snapshot():
    """SharedContext composes the state and vector stores."""
    ctx = SharedContext()
    assert ctx.remember("goal", "build", owner="alpha") == 1
    assert ctx.recall("goal") == "build"
    assert ctx.forget("goal") is True
    assert ctx.recall("goal", "none") == "none"

    entry = ctx.store_vector("m1", [1.0, 0.0], metadata={"note": "first"}, owner="beta")
    assert isinstance(entry, VectorEntry)
    assert ctx.query_vector([1.0, 0.0])[0].vector_id == "m1"

    snapshot = ctx.snapshot()
    assert "state" in snapshot and "vectors" in snapshot

    stats = ctx.stats()
    assert stats["state"]["entries"] == 0
    assert stats["vectors"]["vectors"] == 1

    removed = ctx.reset()
    assert removed == {"state": 0, "vectors": 1}
    assert ctx.vectors.count() == 0


def test_shared_context_locked_context_manager():
    """The locked() context manager guards compound operations."""
    ctx = SharedContext()
    with ctx.locked() as locked_ctx:
        locked_ctx.remember("a", 1)
        locked_ctx.store_vector("v1", [1.0, 0.0])

    assert ctx.recall("a") == 1
    assert ctx.vectors.count() == 1


def test_swarm_agents_share_state_and_vectors():
    """All agents in a swarm observe the same shared context."""
    topology = TDLTopology(agents=[AgentConfig(name="alpha"), AgentConfig(name="beta")])
    swarm = SwarmLifecycleManager(topology=topology)
    alpha = swarm.get_agent("alpha")
    beta = swarm.get_agent("beta")

    alpha.set_shared_state("plan", {"step": 1})
    assert beta.get_shared_state("plan") == {"step": 1}
    assert alpha.shared_context is swarm.get_shared_context()

    assert alpha.compare_and_set_shared_state("plan", {"step": 1}, {"step": 2}) is True
    assert beta.get_shared_state("plan") == {"step": 2}
    assert alpha.compare_and_set_shared_state("plan", {"step": 1}, {"step": 3}) is False

    alpha.store_shared_vector("key1", [1.0, 0.0], metadata={"name": "alpha-note"})
    hits = beta.search_shared_vectors([1.0, 0.0], top_k=1)
    assert hits[0].vector_id == "key1"
    assert hits[0].owner == "alpha"
