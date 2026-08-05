"""
CLI Tooling ('lasb') for N-Dimensional Isolated Sandbox Meshing (AC5).
Provides administrative commands for universe orchestration, zero-trust meshing,
God Mode GraphQL queries, and dashboard serving.
"""

import sys
import argparse
import json
import time
from typing import List, Optional

from .orchestrator import UniverseOrchestrator, UniverseStatus, ComputeQuota
from .mesh import MeshNetworkManager, TrustAction
from .graphql_api import GodModeGraphQLAPI
from .dashboard import DashboardServer

_global_orchestrator = UniverseOrchestrator()
_global_mesh = MeshNetworkManager()
_global_graphql = GodModeGraphQLAPI(_global_orchestrator, _global_mesh)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lasb",
        description="LocalAgentSandbox CLI - The Multi-Verse Agent Ecology",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    uv_parser = subparsers.add_parser("universe", help="Universe sandbox management")
    uv_sub = uv_parser.add_subparsers(dest="action", help="Universe action")

    create_p = uv_sub.add_parser("create", help="Create agent universe sandbox(es)")
    create_p.add_argument("--count", type=int, default=1, help="Number of sandboxes to create (e.g. 1000)")
    create_p.add_argument("--name-prefix", type=str, default="agent-node", help="Name prefix for sandboxes")
    create_p.add_argument("--memory", type=int, default=512, help="Memory quota per sandbox in MB")

    list_p = uv_sub.add_parser("list", help="List running sandboxes")
    list_p.add_argument("--status", type=str, choices=["RUNNING", "PAUSED", "STOPPED", "MESHED"], help="Filter status")
    list_p.add_argument("--limit", type=int, default=50, help="Max items to list")
    list_p.add_argument("--json", action="store_true", help="Output raw JSON")

    get_p = uv_sub.add_parser("get", help="Get universe details")
    get_p.add_argument("universe_id", type=str, help="Universe ID")

    dest_p = uv_sub.add_parser("destroy", help="Destroy universe")
    dest_p.add_argument("universe_id", type=str, help="Universe ID")

    mesh_parser = subparsers.add_parser("mesh", help="Zero-trust mesh network management")
    mesh_sub = mesh_parser.add_subparsers(dest="action", help="Mesh action")

    conn_p = mesh_sub.add_parser("connect", help="Connect two sandboxes over zero-trust mesh")
    conn_p.add_argument("source_id", type=str, help="Source Universe ID")
    conn_p.add_argument("target_id", type=str, help="Target Universe ID")

    top_p = mesh_sub.add_parser("topology", help="View mesh network topology")

    gm_parser = subparsers.add_parser("godmode", help="God Mode GraphQL Observability")
    gm_sub = gm_parser.add_subparsers(dest="action", help="Godmode action")
    query_p = gm_sub.add_parser("query", help="Execute GraphQL query")
    query_p.add_argument("query_str", type=str, help="GraphQL query string")

    dash_parser = subparsers.add_parser("dashboard", help="Start web visualization dashboard")
    dash_parser.add_argument("--host", type=str, default="127.0.0.1", help="Host address")
    dash_parser.add_argument("--port", type=int, default=8080, help="Port number")

    return parser


def main(args: Optional[List[str]] = None) -> int:
    parser = build_parser()
    parsed = parser.parse_args(args)

    if not parsed.subcommand:
        parser.print_help()
        return 0

    if parsed.subcommand == "universe":
        if parsed.action == "create":
            t0 = time.time()
            if parsed.count == 1:
                uv = _global_orchestrator.create_universe(name=f"{parsed.name_prefix}-0")
                print(f"Created universe: {uv.id} ({uv.name}) [Status: {uv.status.value}]")
            else:
                nodes = _global_orchestrator.create_universes_batch(count=parsed.count, name_prefix=parsed.name_prefix)
                elapsed = time.time() - t0
                print(f"Successfully launched {len(nodes)} sandboxes in {elapsed:.4f} seconds!")
                print(f"Sample Sandbox ID: {nodes[0].id} .. {nodes[-1].id}")

        elif parsed.action == "list":
            st = UniverseStatus(parsed.status) if parsed.status else None
            items = _global_orchestrator.list_universes(status=st, limit=parsed.limit)
            if getattr(parsed, "json", False):
                print(json.dumps([u.to_dict() for u in items], indent=2))
            else:
                print(f"{'UNIVERSE ID':<15} {'NAME':<25} {'STATUS':<12} {'VIRTUAL IP':<16}")
                print("-" * 70)
                for u in items:
                    print(f"{u.id:<15} {u.name:<25} {u.status.value:<12} {u.network.virtual_ip:<16}")

        elif parsed.action == "get":
            uv = _global_orchestrator.get_universe(parsed.universe_id)
            if uv:
                print(json.dumps(uv.to_dict(), indent=2))
            else:
                print(f"Error: Universe '{parsed.universe_id}' not found.", file=sys.stderr)
                return 1

        elif parsed.action == "destroy":
            success = _global_orchestrator.destroy_universe(parsed.universe_id)
            if success:
                print(f"Destroyed universe '{parsed.universe_id}'.")
            else:
                print(f"Error: Universe '{parsed.universe_id}' not found.", file=sys.stderr)
                return 1

    elif parsed.subcommand == "mesh":
        if parsed.action == "connect":
            src = _global_orchestrator.get_universe(parsed.source_id)
            tgt = _global_orchestrator.get_universe(parsed.target_id)
            if not src or not tgt:
                print("Error: Source or target universe not found.", file=sys.stderr)
                return 1
            chan = _global_mesh.negotiate_channel(src, tgt)
            if chan and chan.is_active:
                print(f"Successfully established mTLS channel: {chan.channel_id}")
            else:
                print("Failed to establish mesh connection.", file=sys.stderr)
                return 1

        elif parsed.action == "topology":
            topo = _global_mesh.get_mesh_topology()
            print(json.dumps(topo, indent=2))

    elif parsed.subcommand == "godmode":
        if parsed.action == "query":
            res = _global_graphql.execute(parsed.query_str)
            print(json.dumps(res, indent=2))

    elif parsed.subcommand == "dashboard":
        server = DashboardServer(
            orchestrator=_global_orchestrator,
            mesh_manager=_global_mesh,
            host=parsed.host,
            port=parsed.port,
        )
        print(f"Starting Multi-Verse Agent Ecology Visualization Dashboard at http://{parsed.host}:{parsed.port}")
        server.start_blocking()

    return 0


if __name__ == "__main__":
    sys.exit(main())
