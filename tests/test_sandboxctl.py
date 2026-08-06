"""
End-to-end tests for the sandboxctl CLI: trustfile-governed runs, exit-code
contract (0 only when the policy is fully enforced), the signed receipt store,
logs, query, and SBOM export.
"""

import json

from click.testing import CliRunner

from local_agent_sandbox.cli import sandboxctl
from local_agent_sandbox.receipt import ReceiptStore, load_public_key, verify_receipt


def _make_runner() -> CliRunner:
    """Return a CliRunner that captures stdout and stderr separately.

    click>=8.2 always separates the streams; click 8.1 mixes them unless
    ``mix_stderr`` is set explicitly (the parameter was removed in 8.2).
    """
    try:
        return CliRunner(mix_stderr=False)
    except TypeError:  # click>=8.2 removed the mix_stderr parameter
        return CliRunner()

GOOD_TRUSTFILE = """
version: "1"
name: "hello"
resources:
  time_s: 10
"""

DENY_TRUSTFILE = """
version: "1"
name: "deny-profile"
network:
  deny:
    - host: evil.example.com
"""

EXPIRED_TRUSTFILE = """
version: "1"
name: "expired-profile"
expiry: "2000-01-01T00:00:00Z"
"""


def _invoke(tmp_path, *opts, trustfile_text=GOOD_TRUSTFILE):
    trustfile = tmp_path / "trustfile.yaml"
    trustfile.write_text(trustfile_text, encoding="utf-8")
    runner = _make_runner()
    return runner.invoke(
        sandboxctl,
        ["run", str(trustfile), "echo hello", *opts],
        catch_exceptions=False,
    )


def test_run_exits_zero_and_prints_receipt(tmp_path):
    result = _invoke(tmp_path, "--receipt-dir", str(tmp_path / "store"))
    assert result.exit_code == 0
    assert "policy fully enforced" in result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["receipt"]["image"] == "echo hello"
    assert receipt["receipt"]["enforcement"]["fully_enforced"] is True
    assert receipt["key_id"]


def test_run_writes_signed_receipt_to_store(tmp_path):
    keys_dir = tmp_path / "keys"
    store_dir = tmp_path / "store"
    result = _invoke(
        tmp_path,
        "--receipt-dir", str(store_dir),
        "--keys-dir", str(keys_dir),
    )
    assert result.exit_code == 0
    store = ReceiptStore(str(store_dir))
    signed = store.read(json.loads(result.stdout)["receipt"]["id"])
    assert signed is not None
    public_key = load_public_key(str(keys_dir / "ed25519_public.pem"))
    assert verify_receipt(signed, public_key) is True


def test_run_no_write_skips_store(tmp_path):
    result = _invoke(
        tmp_path,
        "--receipt-dir", str(tmp_path / "store"),
        "--no-write",
    )
    assert result.exit_code == 0
    assert list(ReceiptStore(str(tmp_path / "store")).iter_all()) == []


def test_run_with_deny_rule_fails_closed(tmp_path):
    result = _invoke(tmp_path, trustfile_text=DENY_TRUSTFILE)
    assert result.exit_code == 1
    assert "policy NOT fully enforced" in result.stderr
    assert "network" in result.stderr


def test_run_with_expired_profile_fails_closed(tmp_path):
    result = _invoke(tmp_path, trustfile_text=EXPIRED_TRUSTFILE)
    assert result.exit_code == 1
    assert "expiry" in result.stderr


def test_run_invalid_trustfile_exits_two(tmp_path):
    trustfile = tmp_path / "bad.yaml"
    trustfile.write_text('version: "1"\nname: 12345\n', encoding="utf-8")
    runner = _make_runner()
    result = runner.invoke(sandboxctl, ["run", str(trustfile), "echo hi"])
    assert result.exit_code == 2
    assert "Invalid trustfile" in result.stderr


def test_run_rejects_missing_trustfile(tmp_path):
    runner = _make_runner()
    result = runner.invoke(sandboxctl, ["run", str(tmp_path / "nope.yaml"), "echo hi"])
    assert result.exit_code == 2


def test_logs_round_trips_receipt(tmp_path):
    store_dir = tmp_path / "store"
    result = _invoke(tmp_path, "--receipt-dir", str(store_dir))
    receipt_id = json.loads(result.stdout)["receipt"]["id"]

    runner = _make_runner()
    logs = runner.invoke(sandboxctl, ["logs", receipt_id, "--receipt-dir", str(store_dir)])
    assert logs.exit_code == 0
    assert json.loads(logs.stdout)["receipt"]["id"] == receipt_id


def test_logs_unknown_id_fails(tmp_path):
    runner = _make_runner()
    result = runner.invoke(
        sandboxctl, ["logs", "does-not-exist", "--receipt-dir", str(tmp_path / "store")]
    )
    assert result.exit_code == 1
    assert "No receipt found" in result.stderr


def test_query_filters_store(tmp_path):
    store_dir = tmp_path / "store"
    _invoke(tmp_path, "--receipt-dir", str(store_dir))

    runner = _make_runner()
    result = runner.invoke(
        sandboxctl, ["query", "fully_enforced=true", "--receipt-dir", str(store_dir)]
    )
    assert result.exit_code == 0
    assert "1 receipt(s) matched" in result.stderr
    assert "echo hello" in result.output


def test_query_syntax_error_exits_two(tmp_path):
    runner = _make_runner()
    result = runner.invoke(
        sandboxctl, ["query", "exit_code=", "--receipt-dir", str(tmp_path / "store")]
    )
    assert result.exit_code == 2


def test_sbom_export_with_verification(tmp_path):
    store_dir = tmp_path / "store"
    keys_dir = tmp_path / "keys"
    result = _invoke(
        tmp_path,
        "--receipt-dir", str(store_dir),
        "--keys-dir", str(keys_dir),
    )
    receipt_id = json.loads(result.stdout)["receipt"]["id"]

    runner = _make_runner()
    sbom = runner.invoke(
        sandboxctl,
        [
            "sbom", receipt_id,
            "--receipt-dir", str(store_dir),
            "--pubkey", str(keys_dir / "ed25519_public.pem"),
        ],
    )
    assert sbom.exit_code == 0
    doc = json.loads(sbom.stdout)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["serialNumber"] == f"urn:uuid:{receipt_id}"
    prop = next(
        p for p in doc["properties"] if p["name"] == "sandboxctl:signature_valid"
    )
    assert prop["value"] == "true"


def test_sandboxctl_status_cmd():
    runner = _make_runner()
    result = runner.invoke(sandboxctl, ["status"])
    assert result.exit_code == 0
    assert "Kernel Syscall Violations:" in result.output

    result_json = runner.invoke(sandboxctl, ["status", "--json"])
    assert result_json.exit_code == 0
    data = json.loads(result_json.output)
    assert "kernel_violations" in data

    result_reset = runner.invoke(sandboxctl, ["status", "--reset"])
    assert result_reset.exit_code == 0
    assert "reset to zero" in result_reset.output

