from click.testing import CliRunner
from local_agent_sandbox.cli import cli


def test_cli_run_command():
    runner = CliRunner()
    result = runner.invoke(cli, ["run", "echo 'CLI test'"])
    assert result.exit_code == 0
    assert "CLI test" in result.output


def test_cli_blocked_command():
    runner = CliRunner()
    result = runner.invoke(cli, ["run", "rm -rf /"])
    assert "BLOCKED" in result.output
