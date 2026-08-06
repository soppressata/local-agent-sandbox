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
    # Test CLI universe create
    ret = cli_main(["universe", "create", "--count", "5", "--name-prefix", "cli-test"])
    assert ret == 0

    captured = capsys.readouterr()
    assert "Successfully launched 5 sandboxes" in captured.out

    # Test CLI universe list
    ret_list = cli_main(["universe", "list", "--limit", "10"])
    assert ret_list == 0
    captured_list = capsys.readouterr()
    assert "cli-test-0" in captured_list.out

    # Test CLI universe status
    ret_status = cli_main(["universe", "status", "uv-00000"])
    assert ret_status == 0
    captured_status = capsys.readouterr()
    assert '"healthy": true' in captured_status.out

    # Test CLI universe stop
    ret_stop = cli_main(["universe", "stop", "uv-00000"])
    assert ret_stop == 0
    captured_stop = capsys.readouterr()
    assert "Stopped universe 'uv-00000'" in captured_stop.out

    # Test CLI universe start
    ret_start = cli_main(["universe", "start", "uv-00000"])
    assert ret_start == 0
    captured_start = capsys.readouterr()
    assert "Started universe 'uv-00000'" in captured_start.out

    # Test CLI universe destroy
    ret_dest = cli_main(["universe", "destroy", "uv-00000"])
    assert ret_dest == 0
    captured_dest = capsys.readouterr()
    assert "Destroyed universe 'uv-00000'" in captured_dest.out


def test_cli_universe_create_use_rust(capsys):
    ret = cli_main(["universe", "create", "--count", "10", "--name-prefix", "rust-cli-test", "--use-rust"])
    assert ret == 0

    captured = capsys.readouterr()
    assert "Successfully launched 10 sandboxes" in captured.out


def test_dashboard_server_endpoints():
    orchestrator = UniverseOrchestrator()
    orchestrator.create_universes_batch(count=3, name_prefix="dash-node")
    mesh = MeshNetworkManager()

    # Pick dynamic available port
    port = 28089
    server = DashboardServer(orchestrator=orchestrator, mesh_manager=mesh, host="127.0.0.1", port=port)
    server.start()
    time.sleep(0.3)

    try:
        # GET /
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as resp:
            html = resp.read().decode("utf-8")
            assert "Multi-Verse Agent Ecology Dashboard" in html

        # GET /api/metrics
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/metrics") as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert data["metrics"]["total_universes"] == 3
            assert len(data["universes"]) == 3

        # POST /api/graphql
        req_data = json.dumps({"query": "{ systemMetrics { total_universes } }"}).encode("utf-8")
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/graphql", data=req_data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            gql_res = json.loads(resp.read().decode("utf-8"))
            assert gql_res["data"]["systemMetrics"]["total_universes"] == 3
    finally:
        server.stop()
        orchestrator.close()


def test_cli_run_timeout_configuration_and_enforcement(capsys, tmp_path):
    log_file = str(tmp_path / "cli_timeout_result.json")

    # 1. Test CLI task execution success with default timeout
    ret = cli_main(["run", "-o", log_file, "--json", "echo", "hello timeout"])
    assert ret == 0
    captured = capsys.readouterr()
    assert '"status": "SUCCESS"' in captured.out
    assert '"timeout_seconds": 3600' in captured.out

    # 2. Test CLI task execution with custom --timeout flag that times out
    hanging_cmd = "python3 -c 'import time; time.sleep(10)'"
    timeout_log = str(tmp_path / "exceeded_result.json")
    ret_timeout = cli_main(["run", "--timeout", "1", "-o", timeout_log, "--json", "--cmd", hanging_cmd])
    assert ret_timeout == 1
    captured_timeout = capsys.readouterr()
    assert '"status": "TIMEOUT_EXCEEDED"' in captured_timeout.out
    assert '"timeout_seconds": 1' in captured_timeout.out

    with open(timeout_log, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["status"] == "TIMEOUT_EXCEEDED"
    assert data["timeout_seconds"] == 1
    assert "exceeded maximum execution timeout" in data["error"]
