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
