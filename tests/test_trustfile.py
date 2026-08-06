"""
Tests for the trustfile.yaml v1 spec: schema validation, parsing, mounts,
network egress policy, and migration from the legacy SandboxConfig model.
"""

import os

import pytest

from local_agent_sandbox.core import SandboxConfig
from local_agent_sandbox.trustfile import (
    DEFAULT_SYSCALLS,
    EgressRule,
    NetworkPolicy,
    ResourceCaps,
    TrustfileValidationError,
    apply_mounts,
    load_trustfile,
    parse_trustfile,
    sandbox_config_to_trustfile,
    trustfile_digest,
    trustfile_to_yaml,
    validate_schema,
)


def _write(tmp_path, text):
    path = tmp_path / "trustfile.yaml"
    path.write_text(text, encoding="utf-8")
    return str(path)


VALID_MINIMAL = """
version: "1"
name: "hello"
"""

VALID_FULL = """
version: "1"
name: "build-tool"
expiry: "2030-01-01T00:00:00Z"
syscalls:
  - read
  - write
  - openat
network:
  allow:
    - host: pypi.org
    - pattern: "*.pypi.org"
  deny:
    - host: evil.example.com
mounts:
  - host_path: /tmp/source
    container_path: /src
    mode: read-only
  - host_path: /tmp/work
    container_path: /work
    mode: read-write
  - host_path: /etc/hostname
    container_path: /etc/hostname
    mode: masked
resources:
  cpu: 0.5
  mem_mb: 256
  disk_mb: 100
  time_s: 10
secrets:
  - vault_path: vault://agent-token
    env: AGENT_TOKEN
"""


# ---------------------------------------------------------------------------
# Schema validation cases
# ---------------------------------------------------------------------------


def test_schema_accepts_minimal_document():
    assert validate_schema({"version": "1", "name": "hello"}) == []


def test_schema_rejects_missing_required_fields():
    errors = validate_schema({"version": "1"})
    assert any("name" in err for err in errors)


def test_schema_rejects_wrong_version():
    errors = validate_schema({"version": "2", "name": "hello"})
    assert any("version" in err for err in errors)


def test_schema_rejects_unknown_top_level_property():
    errors = validate_schema({"version": "1", "name": "hello", "surprise": 1})
    assert any("surprise" in err for err in errors)


def test_schema_rejects_bad_name_pattern():
    errors = validate_schema({"version": "1", "name": "bad name!"})
    assert any("name" in err for err in errors)


def test_schema_rejects_empty_syscall_allowlist():
    errors = validate_schema(
        {"version": "1", "name": "x", "syscalls": []}
    )
    assert any("syscalls" in err for err in errors)


def test_schema_rejects_duplicate_syscalls():
    errors = validate_schema(
        {"version": "1", "name": "x", "syscalls": ["read", "read"]}
    )
    assert any("unique" in err.lower() for err in errors)


def test_schema_rejects_egress_rule_without_host_or_pattern():
    errors = validate_schema(
        {"version": "1", "name": "x", "network": {"allow": [{"port": 443}]}}
    )
    assert errors


def test_schema_rejects_mount_without_required_fields():
    errors = validate_schema(
        {"version": "1", "name": "x", "mounts": [{"host_path": "/tmp/a"}]}
    )
    assert any("container_path" in err for err in errors)


def test_schema_rejects_invalid_mount_mode():
    errors = validate_schema(
        {
            "version": "1",
            "name": "x",
            "mounts": [
                {
                    "host_path": "/tmp/a",
                    "container_path": "/a",
                    "mode": "write-only",
                }
            ],
        }
    )
    assert any("mode" in err for err in errors)


def test_schema_rejects_negative_resource_caps():
    errors = validate_schema(
        {"version": "1", "name": "x", "resources": {"mem_mb": -5}}
    )
    assert any("mem_mb" in err for err in errors)


def test_schema_rejects_bad_expiry_format():
    errors = validate_schema(
        {"version": "1", "name": "x", "expiry": "not-a-date"}
    )
    assert any("expiry" in err for err in errors)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def test_parse_full_trustfile(tmp_path):
    spec = load_trustfile(_write(tmp_path, VALID_FULL))
    assert spec.version == "1"
    assert spec.name == "build-tool"
    assert spec.syscalls == ["read", "write", "openat"]
    assert len(spec.network.allow) == 2
    assert len(spec.network.deny) == 1
    assert len(spec.mounts) == 3
    assert spec.resources.cpu == 0.5
    assert spec.resources.mem_mb == 256
    assert spec.resources.disk_mb == 100
    assert spec.resources.time_s == 10
    assert spec.secrets[0].vault_path == "vault://agent-token"
    assert spec.secrets[0].env == "AGENT_TOKEN"
    assert spec.expiry is not None


def test_parse_defaults_syscall_allowlist(tmp_path):
    spec = load_trustfile(_write(tmp_path, VALID_MINIMAL))
    assert spec.syscalls == list(DEFAULT_SYSCALLS)
    assert spec.resources == ResourceCaps()


def test_parse_rejects_invalid_yaml(tmp_path):
    with pytest.raises(TrustfileValidationError, match="YAML"):
        load_trustfile(_write(tmp_path, "version: [unclosed"))


def test_parse_collects_all_schema_errors(tmp_path):
    with pytest.raises(TrustfileValidationError) as excinfo:
        load_trustfile(_write(tmp_path, "name: 123\nnetwork: []\n"))
    assert len(excinfo.value.errors) >= 1


def test_parse_rejects_both_host_and_pattern():
    with pytest.raises(TrustfileValidationError):
        parse_trustfile(
            'version: "1"\n'
            "name: x\n"
            "network:\n"
            "  allow:\n"
            "    - host: a.com\n"
            "      pattern: '*.a.com'\n"
        )


def test_trustfile_yaml_round_trip(tmp_path):
    spec = load_trustfile(_write(tmp_path, VALID_FULL))
    reparsed = parse_trustfile(trustfile_to_yaml(spec))
    assert reparsed.model_dump(mode="json") == spec.model_dump(mode="json")


def test_trustfile_digest_is_stable(tmp_path):
    spec = load_trustfile(_write(tmp_path, VALID_FULL))
    assert trustfile_digest(spec) == trustfile_digest(spec)


# ---------------------------------------------------------------------------
# Network egress policy
# ---------------------------------------------------------------------------


def test_egress_exact_host_match():
    policy = NetworkPolicy(allow=[EgressRule(host="pypi.org")])
    assert policy.egress_allowed("pypi.org") is True
    assert policy.egress_allowed("evil.org") is False


def test_egress_glob_pattern_match():
    policy = NetworkPolicy(allow=[EgressRule(pattern="*.pypi.org")])
    assert policy.egress_allowed("files.pypi.org") is True
    assert policy.egress_allowed("pypi.org") is False


def test_egress_deny_overrides_allow():
    policy = NetworkPolicy(
        allow=[EgressRule(pattern="*")],
        deny=[EgressRule(host="evil.example.com")],
    )
    assert policy.egress_allowed("evil.example.com") is False
    assert policy.egress_allowed("good.example.com") is True


def test_egress_empty_allow_permits_all():
    assert NetworkPolicy().egress_allowed("anything.io") is True


# ---------------------------------------------------------------------------
# Filesystem mounts
# ---------------------------------------------------------------------------


def test_apply_mounts_masked_creates_placeholder(tmp_path):
    spec = parse_trustfile(
        'version: "1"\n'
        "name: x\n"
        "mounts:\n"
        "  - host_path: /etc/passwd\n"
        "    container_path: /etc/passwd\n"
        "    mode: masked\n"
    )
    sandbox_dir = tmp_path / "sandbox"
    results = apply_mounts(spec, str(sandbox_dir))
    assert results[0]["ok"] is True
    assert os.path.isdir(results[0]["staged_path"])


def test_apply_mounts_missing_host_fails_open_check(tmp_path):
    spec = parse_trustfile(
        'version: "1"\n'
        "name: x\n"
        "mounts:\n"
        "  - host_path: /nonexistent/source\n"
        "    container_path: /src\n"
        "    mode: read-only\n"
    )
    results = apply_mounts(spec, str(tmp_path / "sandbox"))
    assert results[0]["ok"] is False
    assert "does not exist" in results[0]["detail"]


def test_apply_mounts_read_only_strips_write_bits(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "data.txt").write_text("secret", encoding="utf-8")
    spec = parse_trustfile(
        'version: "1"\n'
        "name: x\n"
        "mounts:\n"
        f"  - host_path: {source}\n"
        "    container_path: /data\n"
        "    mode: read-only\n"
    )
    sandbox_dir = tmp_path / "sandbox"
    results = apply_mounts(spec, str(sandbox_dir))
    staged = results[0]["staged_path"]
    assert results[0]["ok"] is True
    assert os.path.join(staged, "data.txt") == staged + "/data.txt"
    assert os.path.join(staged, "data.txt").endswith("/data.txt")
    staged_file = os.path.join(staged, "data.txt")
    with open(staged_file, encoding="utf-8") as handle:
        assert handle.read() == "secret"
    assert not os.access(staged_file, os.W_OK)


# ---------------------------------------------------------------------------
# Migration from the legacy SandboxConfig model
# ---------------------------------------------------------------------------


def test_migrate_sandbox_config_to_trustfile():
    config = SandboxConfig(
        max_timeout_seconds=7.5,
        max_memory_mb=256,
        max_disk_mb=50,
        max_cpu_cores=2,
    )
    spec = sandbox_config_to_trustfile(config)
    assert spec.version == "1"
    assert spec.resources.time_s == 7.5
    assert spec.resources.mem_mb == 256
    assert spec.resources.disk_mb == 50
    assert spec.resources.cpu == 2.0


def test_migrated_trustfile_is_schema_valid_and_parses(tmp_path):
    spec = sandbox_config_to_trustfile(SandboxConfig())
    rendered = trustfile_to_yaml(spec)
    reparsed = parse_trustfile(rendered)
    assert reparsed.resources == spec.resources
