"""
Cli module for OpenHarness.
Provides core functionality for the cli subsystem.
"""
import click
from local_agent_sandbox.core import LocalAgentSandbox, SandboxConfig
from local_agent_sandbox.observability import monitor
from local_agent_sandbox.tdl import SwarmLifecycleManager, parse_tdl_file


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """LocalAgentSandbox CLI - Sub-10ms Local Process Isolation for AI Coding Agents."""
    pass


@cli.command()
@click.argument("command")
@click.option("--timeout", default=3600.0, help="Maximum execution timeout in seconds (default: 3600).")
@click.option("--dir", default=None, help="Custom sandbox directory path.")
def run(command: str, timeout: float, dir: str):
    """Run a bash command inside isolated local sandbox."""
    config = SandboxConfig(max_timeout_seconds=timeout)
    sandbox = LocalAgentSandbox(config=config, sandbox_dir=dir)

    click.echo(f"⚡ Executing inside sandbox: '{command}'")
    result = sandbox.execute(command)

    if result.blocked:
        click.secho(f"❌ BLOCKED: {result.stderr}", fg="red", bold=True)
        if result.status == "TIMEOUT_EXCEEDED":
            click.secho(f"   Status: {result.status}", fg="red", bold=True)
    else:
        color = "green" if result.exit_code == 0 else "red"
        click.secho(f"Exit Code: {result.exit_code} ({result.duration_ms:.1f}ms)", fg=color, bold=True)
        if result.stdout:
            click.echo(result.stdout)
        if result.stderr:
            click.secho(result.stderr, fg="yellow")

    sandbox.cleanup()


@cli.group()
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


if __name__ == "__main__":
    cli()
