"""
Unit tests for CLI Tooling ('lasb') and Web Dashboard Server (AC5).
"""

import time
import json
import urllib.request
import pytest
from local_agent_sandbox.cli import main as cli_main
from local_agent_sandbox.orchestrator import UniverseOrchestrator
from local_agent_sandbox.mesh import MeshNetworkManager
from local_agent_sandbox.dashboard import DashboardServer


def test_cli_universe_create_and_list(capsys):
    ret = cli_main(["universe", "create", "--count", "5", "--name-prefix", "cli-test"])
    assert ret == 0

    captured = capsys.readouterr()
    assert "Successfully launched 5 sandboxes" in captured.out

    ret_list = cli_main(["universe", "list", "--limit", "10"])
    assert ret_list == 0
    captured_list = capsys.readouterr()
    assert "cli-test-0" in captured_list.out


def test_dashboard_server_endpoints():
    orchestrator = UniverseOrchestrator()
    orchestrator.create_universes_batch(count=3, name_prefix="dash-node")
    mesh = MeshNetworkManager()

    port = 28089
    server = DashboardServer(orchestrator=orchestrator, mesh_manager=mesh, host="127.0.0.1", port=port)
    server.start()
    time.sleep(0.3)

    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as resp:
            html = resp.read().decode("utf-8")
            assert "Multi-Verse Agent Ecology Dashboard" in html

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/metrics") as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert data["metrics"]["total_universes"] == 3
            assert len(data["universes"]) == 3

        req_data = json.dumps({"query": "{ systemMetrics { total_universes } }"}).encode("utf-8")
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/graphql", data=req_data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            gql_res = json.loads(resp.read().decode("utf-8"))
            assert gql_res["data"]["systemMetrics"]["total_universes"] == 3
    finally:
        server.stop()
        orchestrator.close()
