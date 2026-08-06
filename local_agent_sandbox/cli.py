"""
Cli module for OpenHarness.
Provides core functionality for the cli subsystem.
"""
import json
import sys
from typing import List, Optional

import click
import yaml

from local_agent_sandbox.core import LocalAgentSandbox, SandboxConfig
from local_agent_sandbox.isolation import GLOBAL_COUNTERS
from local_agent_sandbox.observability import monitor
from local_agent_sandbox.tdl import SwarmLifecycleManager, parse_tdl_file
from local_agent_sandbox.trustfile import (
    TrustfileValidationError,
    load_trustfile,
    sandbox_config_to_trustfile,
    trustfile_to_yaml,
)
from local_agent_sandbox.receipt import (
    ReceiptStore,
    load_public_key,
    receipt_to_sbom,
    verify_receipt,
)
from local_agent_sandbox.query import QuerySyntaxError, filter_receipts, parse_query
from local_agent_sandbox.run import RunEngine


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """LocalAgentSandbox CLI - Sub-10ms Local Process Isolation for AI Coding Agents."""
    pass


@cli.command()
@click.argument("command")
@click.option("--timeout", default=30.0, help="Maximum execution timeout in seconds.")
@click.option("--dir", default=None, help="Custom sandbox directory path.")
def run(command: str, timeout: float, dir: str):
    """Run a bash command inside isolated local sandbox."""
    config = SandboxConfig(max_timeout_seconds=timeout)
    sandbox = LocalAgentSandbox(config=config, sandbox_dir=dir)
    
    click.echo(f"⚡ Executing inside sandbox: '{command}'")
    result = sandbox.execute(command)

    if result.blocked:
        click.secho(f"❌ BLOCKED: {result.stderr}", fg="red", bold=True)
    else:
        color = "green" if result.exit_code == 0 else "red"
        click.secho(f"Exit Code: {result.exit_code} ({result.duration_ms:.1f}ms)", fg=color, bold=True)
        if result.stdout:
            click.echo(result.stdout)
        if result.stderr:
            click.secho(result.stderr, fg="yellow")

    sandbox.cleanup()


@click.group()
def swarm():
    """Manage and monitor agent swarms defined by TDL topology files."""
    pass


@swarm.command("monitor")
@click.argument("topology_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--interval", default=1.0, help="Dashboard refresh interval in seconds.")
@click.option("--once", is_flag=True, help="Render one dashboard frame and exit.")
@click.option("--frames", default=None, type=int, help="Render exactly N frames then exit.")
@click.option("--no-color", is_flag=True, help="Disable ANSI colors in the dashboard output.")
def swarm_monitor(topology_file: str, interval: float, once: bool, frames: int, no_color: bool):
    """Run a real-time terminal dashboard for the swarm defined in TOPOLOGY_FILE.

    Visualizes the swarm topology tree, per-agent status, and message flows.
    Press Ctrl-C to stop the live dashboard.
    """
    topology = parse_tdl_file(topology_file)
    swarm = SwarmLifecycleManager(topology=topology)
    swarm.spin_up_swarm()
    try:
        monitor(
            swarm,
            interval=interval,
            max_frames=frames,
            once=once,
            use_color=not (no_color or once),
        )
    finally:
        swarm.terminate_swarm()


# ---------------------------------------------------------------------------
# sandboxctl: trustfile-driven runs with a signed receipt ledger
# ---------------------------------------------------------------------------


@click.group()
def sandboxctl():
    """Sandbox control plane: trustfile-governed runs with a signed receipt ledger."""
    pass


@sandboxctl.command("run")
@click.argument("trustfile", type=click.Path(exists=True, dir_okay=False, path_type=str))
@click.argument("image")
@click.option("--receipt-dir", default=None, help="Root of the JSONL receipt store.")
@click.option("--keys-dir", default=None, help="Directory holding the Ed25519 signing keypair.")
@click.option("--no-write", is_flag=True, help="Do not append the receipt to the store.")
def sandboxctl_run(trustfile: str, image: str, receipt_dir: str, keys_dir: str, no_write: bool):
    """Run IMAGE under the TRUSTFILE policy on the local node.

    Prints a machine-readable signed receipt to stdout. The command exits 0
    only if the policy was fully enforced; diagnostics go to stderr.
    """
    try:
        spec = load_trustfile(trustfile)
    except TrustfileValidationError as exc:
        click.secho("Invalid trustfile:", err=True, fg="red")
        for err in exc.errors:
            click.secho(f"  - {err}", err=True, fg="red")
        sys.exit(2)

    engine = RunEngine(
        store=ReceiptStore(receipt_dir),
        keys_dir=keys_dir,
        write_receipt=not no_write,
    )

    receipt, signed = engine.run(spec, image)
    click.echo(json.dumps(signed.model_dump(mode="json"), indent=2))

    click.echo("", err=True)
    if receipt.enforcement.fully_enforced:
        click.secho("policy fully enforced", err=True, fg="green")
        sys.exit(0)
    else:
        click.secho("policy NOT fully enforced", err=True, fg="red")
        for check in receipt.enforcement.checks:
            if not (check.applied and check.ok):
                click.secho(f"  - {check.name}: {check.detail}", err=True, fg="red")
        sys.exit(1)


@sandboxctl.command("logs")
@click.argument("receipt_id")
@click.option("--receipt-dir", default=None, help="Root of the JSONL receipt store.")
def sandboxctl_logs(receipt_id: str, receipt_dir: str):
    """Print the stored signed receipt for RECEIPT_ID."""
    store = ReceiptStore(receipt_dir)
    signed = store.read(receipt_id)
    if signed is None:
        click.secho(f"No receipt found for id {receipt_id}", err=True, fg="red")
        sys.exit(1)
    click.echo(json.dumps(signed.model_dump(mode="json"), indent=2))


@sandboxctl.command("query")
@click.argument("expr")
@click.option("--receipt-dir", default=None, help="Root of the JSONL receipt store.")
def sandboxctl_query(expr: str, receipt_dir: str):
    """Filter the receipt store with a boolean expression.

    Examples:
      sandboxctl query 'exit_code=0 and fully_enforced=true'
      sandboxctl query 'image=build-tool'
      sandboxctl query 'duration_ms>100'
      sandboxctl query 'not blocked=true'
    """
    try:
        parsed = parse_query(expr)
    except QuerySyntaxError as exc:
        click.secho(str(exc), err=True, fg="red")
        sys.exit(2)

    store = ReceiptStore(receipt_dir)
    matches = filter_receipts(list(store.iter_all()), parsed)
    for signed in matches:
        receipt = signed.receipt
        click.echo(
            f"{receipt.id}\t{receipt.image}\texit={receipt.exit_code}"
            f"\tenforced={str(receipt.enforcement.fully_enforced).lower()}"
        )
    click.secho(f"{len(matches)} receipt(s) matched", err=True)


@sandboxctl.command("sbom")
@click.argument("receipt_id")
@click.option("--receipt-dir", default=None, help="Root of the JSONL receipt store.")
@click.option("--pubkey", default=None, help="Public key used to verify the receipt signature.")
def sandboxctl_sbom(receipt_id: str, receipt_dir: str, pubkey: Optional[str]):
    """Export an SBOM-style audit document for a stored receipt."""
    store = ReceiptStore(receipt_dir)
    signed = store.read(receipt_id)
    if signed is None:
        click.secho(f"No receipt found for id {receipt_id}", err=True, fg="red")
        sys.exit(1)
    signature_valid = None
    if pubkey:
        public_key_bytes = load_public_key(pubkey)
        signature_valid = verify_receipt(signed, public_key_bytes)
    click.echo(json.dumps(receipt_to_sbom(signed, signature_valid=signature_valid), indent=2))


@sandboxctl.command("migrate-config")
@click.argument("config_file", type=click.Path(exists=True, dir_okay=False, path_type=str))
@click.argument("output", type=click.Path(dir_okay=False), required=False)
def sandboxctl_migrate_config(config_file: str, output: Optional[str]):
    """Convert a legacy SandboxConfig (JSON or YAML) into a trustfile.yaml v1 profile."""
    try:
        with open(config_file, "r", encoding="utf-8") as handle:
            text = handle.read()
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = yaml.safe_load(text)
        config = SandboxConfig.model_validate(data or {})
    except Exception as exc:  # noqa: BLE001 - user-facing CLI error
        click.secho(f"Failed to read legacy config: {exc}", err=True, fg="red")
        sys.exit(2)

    spec = sandbox_config_to_trustfile(config)
    rendered = trustfile_to_yaml(spec)
    if output:
        with open(output, "w", encoding="utf-8") as handle:
            handle.write(rendered)
        click.secho(f"Wrote trustfile to {output}", err=True)
    else:
        click.echo(rendered)


@sandboxctl.command("status")
@click.option("--json", "json_format", is_flag=True, help="Output status in JSON format")
@click.option("--reset", is_flag=True, help="Reset live enforcement counters to zero")
def sandboxctl_status(json_format: bool, reset: bool):
    """Display live policy enforcement counters."""
    if reset:
        GLOBAL_COUNTERS.reset()
        click.echo("Live enforcement counters reset to zero.")
        return
    data = GLOBAL_COUNTERS.to_dict()
    if json_format:
        click.echo(json.dumps(data, indent=2))
    else:
        click.echo("=== Sandbox Live Policy Enforcement Status ===")
        click.echo(f"Kernel Syscall Violations:   {data['kernel_violations']}")
        click.echo(f"Filesystem Mount Violations: {data['filesystem_violations']}")
        click.echo(f"Network Egress Denied:       {data['network_egress_denied']}")
        click.echo(f"Network Egress Allowed:      {data['network_egress_allowed']}")
        click.echo(f"Resource Overrun Violations: {data['resource_overrun_violations']}")
        click.echo(f"Secret Vault Accesses:       {data['secret_vault_accesses']}")
        click.echo(f"Total Policy Violations:     {data['total_violations']}")


cli.add_command(swarm)
cli.add_command(sandboxctl)


def main(args: Optional[List[str]] = None) -> int:
    """Main CLI entry point for sandboxctl and status command."""
    if args is None:
        args = sys.argv[1:]

    if args and args[0] == "status":
        json_flag = "--json" in args
        reset_flag = "--reset" in args
        if reset_flag:
            GLOBAL_COUNTERS.reset()
            print("Live enforcement counters reset to zero.")
            return 0
        data = GLOBAL_COUNTERS.to_dict()
        if json_flag:
            print(json.dumps(data, indent=2))
        else:
            print("=== Sandbox Live Policy Enforcement Status ===")
            print(f"Kernel Syscall Violations:   {data['kernel_violations']}")
            print(f"Filesystem Mount Violations: {data['filesystem_violations']}")
            print(f"Network Egress Denied:       {data['network_egress_denied']}")
            print(f"Network Egress Allowed:      {data['network_egress_allowed']}")
            print(f"Resource Overrun Violations: {data['resource_overrun_violations']}")
            print(f"Secret Vault Accesses:       {data['secret_vault_accesses']}")
            print(f"Total Policy Violations:     {data['total_violations']}")
        return 0

    try:
        sandboxctl.main(args=args, standalone_mode=False)
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 1


if __name__ == "__main__":
    cli()


"""
CLI Tooling ('lasb') for N-Dimensional Isolated Sandbox Meshing (AC5).
Provides administrative commands for universe orchestration, zero-trust meshing,
God Mode GraphQL queries, dashboard serving, and onboarding.
"""

import sys
import os
import argparse
import json
import time
from typing import List, Optional

from .orchestrator import UniverseOrchestrator, UniverseStatus, ComputeQuota
from .isolation import GLOBAL_COUNTERS
from .rust_orchestrator import RustOrchestratorBridge
from .mesh import MeshNetworkManager, TrustAction
from .graphql_api import GodModeGraphQLAPI
from .dashboard import DashboardServer
from .onboarding import OnboardingWizard
from .pipeline_generator import AIPipelineGenerator
from .self_healing import SelfHealingEngine
from .diagnostics import DiagnosisReport
from .fleet import (
    handle_fleet_init,
    handle_fleet_join,
    handle_fleet_run,
    handle_fleet_status,
    handle_fleet_dashboard,
    handle_fleet_migrate,
)

# Shared global singleton orchestrator instance for CLI daemon mode
_global_orchestrator = UniverseOrchestrator()
_global_mesh = MeshNetworkManager()
_global_graphql = GodModeGraphQLAPI(_global_orchestrator, _global_mesh)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lasb",
        description="LocalAgentSandbox CLI - The Multi-Verse Agent Ecology",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # Onboarding command group
    onboard_p = subparsers.add_parser("onboard", help="Run guided onboarding and setup wizard")
    onboard_p.add_argument("--interactive", action="store_true", help="Run interactive prompts")
    onboard_p.add_argument("--name-prefix", type=str, default="agent-node", help="Default sandbox name prefix")
    onboard_p.add_argument("--memory", type=int, default=512, help="Default memory quota per sandbox in MB")
    onboard_p.add_argument("--port", type=int, default=8080, help="Default dashboard port")
    onboard_p.add_argument("--no-sandbox", action="store_true", help="Skip creating initial sandbox")

    init_p = subparsers.add_parser("init", help="Alias for onboard command")
    init_p.add_argument("--interactive", action="store_true", help="Run interactive prompts")
    init_p.add_argument("--name-prefix", type=str, default="agent-node", help="Default sandbox name prefix")
    init_p.add_argument("--memory", type=int, default=512, help="Default memory quota per sandbox in MB")
    init_p.add_argument("--port", type=int, default=8080, help="Default dashboard port")
    init_p.add_argument("--no-sandbox", action="store_true", help="Skip creating initial sandbox")

    # Self-Healing & Remediation command group
    heal_parser = subparsers.add_parser("self-heal", help="Generate code patch, verify in isolated sandbox, and format diff for review")
    heal_parser.add_argument("--target-file", type=str, required=True, help="Target file path requiring repair")
    heal_parser.add_argument("--error-type", type=str, default="ZeroDivisionError", help="Error type string")
    heal_parser.add_argument("--root-cause", type=str, default="Division by zero encountered", help="Root cause explanation")
    heal_parser.add_argument("--suggested-fix", type=str, default="Add zero-check guardrail", help="Suggested fix description")
    heal_parser.add_argument("--original-code-file", type=str, default=None, help="File path containing original code")
    heal_parser.add_argument("--provider", type=str, default="google", choices=["google", "openai", "anthropic"], help="LLM Provider adapter")
    heal_parser.add_argument("--model", type=str, default=None, help="LLM model name")
    heal_parser.add_argument("--api-key", type=str, default=None, help="API key for LLM provider")
    heal_parser.add_argument("--json", action="store_true", help="Output remediation report in JSON format")
    heal_parser.add_argument("-o", "--output", type=str, help="File path to save the remediation report")

    # AI Pipeline Generation command group
    gen_parser = subparsers.add_parser("ai-generate", help="Generate AI deployment pipeline execution plan and architecture docs")
    gen_parser.add_argument("prompt", type=str, nargs="?", default="", help="Natural language prompt describing desired deployment state")
    gen_parser.add_argument("-p", "--prompt", dest="prompt_flag", type=str, help="Alternative flag for natural language prompt")
    gen_parser.add_argument("--provider", type=str, default="google", choices=["google", "openai", "anthropic"], help="LLM Provider adapter")
    gen_parser.add_argument("--model", type=str, default=None, help="LLM model name")
    gen_parser.add_argument("--api-key", type=str, default=None, help="API key for LLM provider")
    gen_parser.add_argument("--json", action="store_true", help="Output execution plan and architecture docs in JSON format")
    gen_parser.add_argument("-o", "--output", type=str, help="File path to save the generated execution plan")

    # Universe command group
    uv_parser = subparsers.add_parser("universe", help="Universe sandbox management")
    uv_sub = uv_parser.add_subparsers(dest="action", help="Universe action")

    # universe create
    create_p = uv_sub.add_parser("create", help="Create agent universe sandbox(es)")
    create_p.add_argument("--count", type=int, default=1, help="Number of sandboxes to create (e.g. 1000)")
    create_p.add_argument("--name-prefix", type=str, default="agent-node", help="Name prefix for sandboxes")
    create_p.add_argument("--memory", type=int, default=512, help="Memory quota per sandbox in MB")
    create_p.add_argument("--use-rust", action="store_true", help="Use Rust core orchestrator bridge")

    # universe list
    list_p = uv_sub.add_parser("list", help="List running sandboxes")
    list_p.add_argument("--status", type=str, choices=["RUNNING", "PAUSED", "STOPPED", "MESHED"], help="Filter status")
    list_p.add_argument("--limit", type=int, default=50, help="Max items to list")
    list_p.add_argument("--json", action="store_true", help="Output raw JSON")

    # universe get
    get_p = uv_sub.add_parser("get", help="Get universe details")
    get_p.add_argument("universe_id", type=str, help="Universe ID")

    # universe status
    status_p = uv_sub.add_parser("status", help="Get universe status and health details")
    status_p.add_argument("universe_id", type=str, help="Universe ID")

    # universe start
    start_p = uv_sub.add_parser("start", help="Start universe sandbox")
    start_p.add_argument("universe_id", type=str, help="Universe ID")

    # universe stop
    stop_p = uv_sub.add_parser("stop", help="Stop universe sandbox")
    stop_p.add_argument("universe_id", type=str, help="Universe ID")

    # universe destroy
    dest_p = uv_sub.add_parser("destroy", help="Destroy universe")
    dest_p.add_argument("universe_id", type=str, help="Universe ID")

    # Mesh command group
    mesh_parser = subparsers.add_parser("mesh", help="Zero-trust mesh network management")
    mesh_sub = mesh_parser.add_subparsers(dest="action", help="Mesh action")

    # mesh connect
    conn_p = mesh_sub.add_parser("connect", help="Connect two sandboxes over zero-trust mesh")
    conn_p.add_argument("source_id", type=str, help="Source Universe ID")
    conn_p.add_argument("target_id", type=str, help="Target Universe ID")

    # mesh topology
    top_p = mesh_sub.add_parser("topology", help="View mesh network topology")

    # Godmode command group
    gm_parser = subparsers.add_parser("godmode", help="God Mode GraphQL Observability")
    gm_sub = gm_parser.add_subparsers(dest="action", help="Godmode action")
    query_p = gm_sub.add_parser("query", help="Execute GraphQL query")
    query_p.add_argument("query_str", type=str, help="GraphQL query string")

    # Dashboard command group
    dash_parser = subparsers.add_parser("dashboard", help="Start web visualization dashboard")
    dash_parser.add_argument("--host", type=str, default="127.0.0.1", help="Host address")
    dash_parser.add_argument("--port", type=int, default=8080, help="Port number")

    # HarnessFleet command group
    fleet_parser = subparsers.add_parser("fleet", help="Distributed, Self-Healing AI Test Grid management")
    fleet_sub = fleet_parser.add_subparsers(dest="fleet_action", help="Fleet subcommands")

    fleet_init = fleet_sub.add_parser("init", help="Generate fleet.yaml configuration file")
    fleet_init.add_argument("--cluster-name", type=str, default="harness-fleet-primary", help="Name of cluster")
    fleet_init.add_argument("-o", "--output", type=str, default="fleet.yaml", help="Output config path")

    fleet_migrate = fleet_sub.add_parser("migrate", help="Migrate existing configs into fleet.yaml")
    fleet_migrate.add_argument("--source", type=str, default=None, help="Source config file path")
    fleet_migrate.add_argument("-o", "--output", type=str, default="fleet.yaml", help="Output config path")

    fleet_join = fleet_sub.add_parser("join", help="Worker node onboarding zero-config join")
    fleet_join.add_argument("--token", type=str, help="Enrollment token")
    fleet_join.add_argument("--conductor", type=str, default="127.0.0.1:9443", help="Conductor address")

    fleet_run = fleet_sub.add_parser("run", help="Execute distributed test run across grid")
    fleet_run.add_argument("test_files", nargs="*", help="Test file paths")
    fleet_run.add_argument("--shards", type=str, default="auto", help="Shards balancing strategy")
    fleet_run.add_argument("--nodes", type=int, default=4, help="Target worker node count")
    fleet_run.add_argument("--timeout", type=int, default=300, help="Run timeout in seconds")
    fleet_run.add_argument("--resume", action="store_true", help="Resume from last checkpoint")

    fleet_status = fleet_sub.add_parser("status", help="Display grid health and node status table")

    fleet_dash = fleet_sub.add_parser("dashboard", help="Launch fleet real-time observability dashboard")

    # Status / Policy Enforcement Counters command
    status_p = subparsers.add_parser("status", help="Display live policy enforcement counters")
    status_p.add_argument("--json", action="store_true", help="Output status in JSON format")
    status_p.add_argument("--reset", action="store_true", help="Reset live enforcement counters to zero")

    return parser


def main(args: Optional[List[str]] = None) -> int:
    parser = build_parser()
    parsed = parser.parse_args(args)

    if not parsed.subcommand:
        parser.print_help()
        print("\nTip: Run 'lasb onboard' or 'lasb init' for guided quickstart setup.")
        return 0

    if parsed.subcommand == "status":
        if getattr(parsed, "reset", False):
            GLOBAL_COUNTERS.reset()
            print("Live enforcement counters reset to zero.")
            return 0
        data = GLOBAL_COUNTERS.to_dict()
        if getattr(parsed, "json", False):
            print(json.dumps(data, indent=2))
        else:
            print("=== Sandbox Live Policy Enforcement Status ===")
            print(f"Kernel Syscall Violations:   {data['kernel_violations']}")
            print(f"Filesystem Mount Violations: {data['filesystem_violations']}")
            print(f"Network Egress Denied:       {data['network_egress_denied']}")
            print(f"Network Egress Allowed:      {data['network_egress_allowed']}")
            print(f"Resource Overrun Violations: {data['resource_overrun_violations']}")
            print(f"Secret Vault Accesses:       {data['secret_vault_accesses']}")
            print(f"Total Policy Violations:     {data['total_violations']}")
        return 0

    if parsed.subcommand in ("onboard", "init"):
        wizard = OnboardingWizard()
        wizard.execute_onboarding(
            interactive=getattr(parsed, "interactive", False),
            name_prefix=getattr(parsed, "name_prefix", "agent-node"),
            memory_mb=getattr(parsed, "memory", 512),
            dashboard_port=getattr(parsed, "port", 8080),
            create_initial_sandbox=not getattr(parsed, "no_sandbox", False),
            orchestrator=_global_orchestrator,
            verbose=True,
        )
        return 0

    if parsed.subcommand == "universe":
        if parsed.action == "create":
            t0 = time.time()
            if getattr(parsed, "use_rust", False):
                bridge = RustOrchestratorBridge(use_rust=True, orchestrator=_global_orchestrator)
                nodes = bridge.batch_create(count=parsed.count, name_prefix=parsed.name_prefix)
                elapsed = time.time() - t0
                print(f"Successfully launched {len(nodes)} sandboxes using Rust bridge in {elapsed:.4f} seconds!")
                if nodes:
                    print(f"Sample Sandbox ID: {nodes[0].id} .. {nodes[-1].id}")
            elif parsed.count == 1:
                quota = ComputeQuota(memory_mb=parsed.memory)
                uv = _global_orchestrator.create_universe(name=f"{parsed.name_prefix}-0", quota=quota)
                print(f"Created universe: {uv.id} ({uv.name}) [Status: {uv.status.value if isinstance(uv.status, UniverseStatus) else uv.status}]")
            else:
                quota = ComputeQuota(memory_mb=parsed.memory)
                nodes = _global_orchestrator.create_universes_batch(count=parsed.count, name_prefix=parsed.name_prefix, template_quota=quota)
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
                    st_val = u.status.value if isinstance(u.status, UniverseStatus) else str(u.status)
                    print(f"{u.id:<15} {u.name:<25} {st_val:<12} {u.network.virtual_ip:<16}")

        elif parsed.action in ("status", "get"):
            uv = _global_orchestrator.get_universe(parsed.universe_id)
            if uv:
                info = uv.to_dict()
                info["health"] = uv.health_check()
                print(json.dumps(info, indent=2))
            else:
                print(f"Error: Universe '{parsed.universe_id}' not found.", file=sys.stderr)
                return 1

        elif parsed.action == "start":
            success = _global_orchestrator.start_universe(parsed.universe_id)
            if success:
                print(f"Started universe '{parsed.universe_id}'.")
            else:
                print(f"Error: Universe '{parsed.universe_id}' not found.", file=sys.stderr)
                return 1

        elif parsed.action == "stop":
            success = _global_orchestrator.stop_universe(parsed.universe_id)
            if success:
                print(f"Stopped universe '{parsed.universe_id}'.")
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

    elif parsed.subcommand == "self-heal":
        target_file = parsed.target_file
        orig_code = ""
        if getattr(parsed, "original_code_file", None) and os.path.exists(parsed.original_code_file):
            with open(parsed.original_code_file, "r", encoding="utf-8") as f:
                orig_code = f.read()
        else:
            orig_code = "def process_data(val, div):\n    return val / div\n"

        diagnosis = DiagnosisReport(
            step_id="step-cli-repair",
            step_name="CLI Repair Task",
            error_type=parsed.error_type,
            root_cause=parsed.root_cause,
            summary=f"CLI failure trigger: {parsed.error_type}",
            suggested_fix=parsed.suggested_fix,
            confidence_score=0.9,
            provider=parsed.provider,
        )

        engine = SelfHealingEngine(
            provider=getattr(parsed, "provider", "google"),
            api_key=getattr(parsed, "api_key", None),
            model=getattr(parsed, "model", None),
            orchestrator=_global_orchestrator,
        )

        report = engine.remediate_failure(
            diagnosis=diagnosis,
            target_file=target_file,
            original_code=orig_code,
        )

        if getattr(parsed, "json", False):
            output_str = json.dumps(report.to_dict(), indent=2)
        else:
            output_str = report.format_review_text()

        output_path = getattr(parsed, "output", None)
        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(output_str)
            print(f"Self-healing remediation report saved to {output_path}")
        else:
            print(output_str)
        return 0

    elif parsed.subcommand == "ai-generate":
        prompt = getattr(parsed, "prompt", None) or getattr(parsed, "prompt_flag", None)
        if not prompt:
            print("Error: A natural language prompt is required.", file=sys.stderr)
            return 1
        generator = AIPipelineGenerator(
            provider=getattr(parsed, "provider", "google"),
            api_key=getattr(parsed, "api_key", None),
            model=getattr(parsed, "model", None),
        )
        result = generator.generate_pipeline(prompt)
        if getattr(parsed, "json", False):
            output_str = json.dumps(result.to_dict(), indent=2)
        else:
            output_str = result.format_text()

        output_path = getattr(parsed, "output", None)
        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(output_str)
            print(f"Pipeline generation plan saved to {output_path}")
        else:
            print(output_str)
        return 0

    elif parsed.subcommand == "dashboard":
        server = DashboardServer(
            orchestrator=_global_orchestrator,
            mesh_manager=_global_mesh,
            host=parsed.host,
            port=parsed.port,
        )
        print(f"Starting Multi-Verse Agent Ecology Visualization Dashboard at http://{parsed.host}:{parsed.port}")
        server.start_blocking()

    elif parsed.subcommand == "fleet":
        action = getattr(parsed, "fleet_action", None)
        if action == "init":
            handle_fleet_init(cluster_name=parsed.cluster_name, output_path=parsed.output)
            return 0
        elif action == "migrate":
            handle_fleet_migrate(source_file=parsed.source, output_path=parsed.output)
            return 0
        elif action == "join":
            handle_fleet_join(conductor_address=parsed.conductor, token=parsed.token)
            return 0
        elif action == "run":
            return handle_fleet_run(
                test_files=parsed.test_files,
                shards=parsed.shards,
                nodes_count=parsed.nodes,
                timeout=parsed.timeout,
                resume=parsed.resume,
            )
        elif action == "status":
            handle_fleet_status()
            return 0
        elif action == "dashboard":
            handle_fleet_dashboard()
            return 0
        else:
            print("Usage: lasb fleet [init|migrate|join|run|status|dashboard]")
    return 0


cli = main
sandboxctl = main


if __name__ == "__main__":
    sys.exit(main())
