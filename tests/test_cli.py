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


def test_cli_run_with_timeout_flag():
    runner = CliRunner()
    result = runner.invoke(cli, ["run", "--timeout", "0.5", "sleep 2"])
    assert result.exit_code == 0
    assert "timed out" in result.output
    assert "TIMEOUT_EXCEEDED" in result.output


def test_cli_run_default_timeout_is_one_hour():
    runner = CliRunner()
    result = runner.invoke(cli, ["run", "--help"])
    assert result.exit_code == 0
    assert "--timeout" in result.output
    assert "3600" in result.output
