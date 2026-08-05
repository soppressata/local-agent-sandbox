"""
Unit tests for GraphQL God Mode Observability Engine (AC3).
"""

import pytest
from local_agent_sandbox.orchestrator import UniverseOrchestrator
from local_agent_sandbox.mesh import MeshNetworkManager
from local_agent_sandbox.graphql_api import GodModeGraphQLAPI


def test_graphql_system_metrics_query():
    orchestrator = UniverseOrchestrator()
    orchestrator.create_universes_batch(5, name_prefix="gm-node")
    mesh = MeshNetworkManager()
    graphql = GodModeGraphQLAPI(orchestrator, mesh)

    query = """
    query GodModeMetrics {
        systemMetrics {
            total_universes
            running_universes
        }
    }
    """
    res = graphql.execute(query)
    assert "data" in res
    assert res["data"]["systemMetrics"]["total_universes"] == 5
    assert res["data"]["systemMetrics"]["running_universes"] == 5
    orchestrator.close()


def test_graphql_universe_and_filesystem_query():
    orchestrator = UniverseOrchestrator()
    uv = orchestrator.create_universe(name="gm-target")
    uv.write_virtual_file("/etc/agent_policy.json", '{"policy": "strict"}')

    mesh = MeshNetworkManager()
    graphql = GodModeGraphQLAPI(orchestrator, mesh)

    query = f"""
    query GetUniverseDetails {{
        universe(id: "{uv.id}") {{
            id
            name
            status
        }}
        filesystemChanges(universeId: "{uv.id}") {{
            path
            action
        }}
    }}
    """
    res = graphql.execute(query)
    assert res["data"]["universe"]["id"] == uv.id
    assert len(res["data"]["filesystemChanges"]) == 1
    assert res["data"]["filesystemChanges"][0]["path"] == "/etc/agent_policy.json"
    orchestrator.close()


def test_graphql_mutations():
    orchestrator = UniverseOrchestrator()
    mesh = MeshNetworkManager()
    graphql = GodModeGraphQLAPI(orchestrator, mesh)

    mutation = """
    mutation CreateBatch {
        createUniverses(count: 3) {
            id
            name
        }
    }
    """
    res = graphql.execute(mutation)
    created = res["data"]["createUniverses"]
    assert len(created) == 3
    assert len(orchestrator.universes) == 3
    orchestrator.close()
