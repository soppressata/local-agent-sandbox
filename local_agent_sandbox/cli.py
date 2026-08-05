"""
Cli module for OpenHarness.
Provides core functionality for the cli subsystem.
"""
import click
from local_agent_sandbox.core import LocalAgentSandbox, SandboxConfig


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


if __name__ == "__main__":
    cli()
