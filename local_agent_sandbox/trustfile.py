"""
Trustfile v1 specification.

A trustfile is a YAML document that declares the security profile a workload
must run under: a syscall allowlist, network egress rules (allow/deny by host
or glob pattern), filesystem mounts (read-only / read-write / masked), resource
caps (cpu / memory / disk / wall-time), secret vault paths, and an optional
expiry.

This module provides the formal JSON Schema for ``trustfile.yaml`` v1 plus a
self-contained validator for the schema keyword subset it uses, and the
migration helper that translates a legacy :class:`SandboxConfig` into an
equivalent trustfile profile.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shutil
import stat
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Tuple, Union

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from .core import SandboxConfig


class TrustfileValidationError(ValueError):
    """Raised when a trustfile fails schema or model validation."""

    def __init__(self, errors: List[str]) -> None:
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_SYSCALLS = (
    # Process / memory
    "read", "write", "open", "openat", "close", "stat", "lstat", "fstat",
    "newfstatat", "mmap", "munmap", "mprotect", "brk", "madvise", "access",
    "faccessat", "faccessat2", "futex", "rseq", "prlimit64", "set_robust_list",
    "get_robust_list", "arch_prctl", "clone", "clone3", "fork", "vfork",
    "execve", "execveat", "exit", "exit_group", "wait4", "waitid",
    # Namespace / id
    "uname", "getuid", "geteuid", "getgid", "getegid", "getpid", "getppid",
    "gettid", "getpgid", "getpgrp", "setuid", "setgid", "setsid",
    # Filesystem / directory
    "getdents", "getdents64", "readlink", "readlinkat", "lseek", "getcwd",
    "chdir", "fchdir", "mkdir", "mkdirat", "unlink", "unlinkat", "rmdir",
    "rename", "renameat", "renameat2", "symlink", "symlinkat", "link",
    "linkat", "chmod", "fchmod", "fchmodat", "umask", "statfs", "fstatfs",
    "statx", "dup", "dup2", "dup3", "fcntl", "fcntl64", "flock", "fsync",
    "fdatasync", "truncate", "ftruncate", "utimensat", "utime", "fchown",
    "fchownat", "chown", "lchown",
    # IO
    "writev", "readv", "pread64", "pwrite64", "ioctl", "poll", "ppoll",
    "select", "pselect6", "epoll_create1", "epoll_ctl", "epoll_wait",
    "eventfd2", "pipe", "pipe2", "splice", "sendfile",
    # Network
    "socket", "socketpair", "connect", "bind", "listen", "accept",
    "accept4", "sendto", "recvfrom", "sendmsg", "recvmsg", "getsockopt",
    "setsockopt", "getpeername", "getsockname", "shutdown", "getaddrinfo",
    "getnameinfo",
    # Time / signals / misc
    "nanosleep", "clock_gettime", "clock_getres", "clock_nanosleep", "time",
    "gettimeofday", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
    "sigaltstack", "getrandom", "getrlimit", "setrlimit", "kill", "tgkill",
    "tkill", "getpriority", "setpriority", "sched_yield", "sched_getaffinity",
    "mlock", "mlockall", "munlock", "munlockall", "sysinfo",
)

# ---------------------------------------------------------------------------
# JSON Schema (v1) + self-contained validator
# ---------------------------------------------------------------------------

TRUSTFILE_SCHEMA_V1: Dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "https://local-agent-sandbox.dev/schemas/trustfile-v1.json",
    "title": "Trustfile v1",
    "type": "object",
    "additionalProperties": False,
    "required": ["version", "name"],
    "properties": {
        "version": {"type": "string", "const": "1"},
        "name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
        },
        "expiry": {
            "type": "string",
            "pattern": r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}:\d{2}(\.\d+)?"
            r"(Z|[+-]\d{2}:\d{2})?)?$",
        },
        "syscalls": {
            "type": "array",
            "minItems": 1,
            "uniqueItems": True,
            "items": {"type": "string", "minLength": 1, "pattern": r"^[a-z0-9_]+$"},
        },
        "network": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "allow": {
                    "type": "array",
                    "items": {"$ref": "#/definitions/egressRule"},
                },
                "deny": {
                    "type": "array",
                    "items": {"$ref": "#/definitions/egressRule"},
                },
            },
        },
        "mounts": {
            "type": "array",
            "items": {"$ref": "#/definitions/mount"},
        },
        "resources": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "cpu": {"type": "number", "minimum": 0.01},
                "mem_mb": {"type": "integer", "minimum": 1},
                "disk_mb": {"type": "integer", "minimum": 1},
                "time_s": {"type": "number", "minimum": 0.1},
            },
        },
        "secrets": {
            "type": "array",
            "items": {"$ref": "#/definitions/secretRef"},
        },
    },
    "definitions": {
        "egressRule": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "host": {
                    "type": "string",
                    "minLength": 1,
                    "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
                },
                "pattern": {"type": "string", "minLength": 2},
            },
            "anyOf": [
                {"required": ["host"]},
                {"required": ["pattern"]},
            ],
        },
        "mount": {
            "type": "object",
            "additionalProperties": False,
            "required": ["host_path", "container_path", "mode"],
            "properties": {
                "host_path": {"type": "string", "minLength": 1},
                "container_path": {"type": "string", "minLength": 1},
                "mode": {"enum": ["read-only", "read-write", "masked"]},
            },
        },
        "secretRef": {
            "type": "object",
            "additionalProperties": False,
            "required": ["vault_path"],
            "properties": {
                "vault_path": {"type": "string", "minLength": 3},
                "env": {
                    "type": "string",
                    "pattern": r"^[A-Za-z_][A-Za-z0-9_]*$",
                },
            },
        },
    },
}

_SUPPORTED_KEYWORDS = frozenset(
    {
        "type", "properties", "additionalProperties", "required", "items",
        "enum", "const", "pattern", "minimum", "maximum", "minLength",
        "maxLength", "uniqueItems", "minItems", "maxItems", "$ref",
        "anyOf", "oneOf", "allOf",
    }
)


def _refs(schema: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Extract ``definitions`` from a schema into a name -> schema map."""
    return dict(schema.get("definitions", {}))


def _matches_type(instance: Any, expected: str) -> bool:
    """Check an instance against a JSON Schema ``type`` keyword value."""
    if expected == "object":
        return isinstance(instance, dict)
    if expected == "array":
        return isinstance(instance, list)
    if expected == "string":
        return isinstance(instance, str)
    if expected == "boolean":
        return isinstance(instance, bool)
    if expected == "null":
        return instance is None
    if expected == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if expected == "number":
        return isinstance(instance, (int, float)) and not isinstance(instance, bool)
    return True


def _hashable(value: Any) -> Any:
    """Recursively convert a value into a hashable form for uniqueItems."""
    if isinstance(value, list):
        return tuple(_hashable(v) for v in value)
    if isinstance(value, dict):
        return tuple(sorted((k, _hashable(v)) for k, v in value.items()))
    return value


def _validate_instance(
    instance: Any,
    schema: Dict[str, Any],
    refs: Dict[str, Dict[str, Any]],
    errors: List[str],
    path: str,
) -> None:
    """Validate ``instance`` against a single schema node, appending errors."""
    if "$ref" in schema:
        name = schema["$ref"].rsplit("/", 1)[-1]
        if name not in refs:
            errors.append(f"{path}: unknown $ref {schema['$ref']!r}")
            return
        schema = refs[name]

    if "type" in schema and not _matches_type(instance, schema["type"]):
        errors.append(
            f"{path}: expected type {schema['type']!r}, got {type(instance).__name__}"
        )
        return

    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected {schema['const']!r}, got {instance!r}")

    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: value {instance!r} not in enum {schema['enum']!r}")

    if isinstance(instance, dict):
        props = schema.get("properties", {})
        if "additionalProperties" in schema:
            additional = schema["additionalProperties"]
            if additional is False:
                for key in sorted(set(instance) - set(props)):
                    errors.append(f"{path}: additional property {key!r} not allowed")
            elif isinstance(additional, dict):
                for key in sorted(set(instance) - set(props)):
                    _validate_instance(
                        instance[key], additional, refs, errors, f"{path}.{key}"
                    )
        for key, sub in props.items():
            if key in instance:
                _validate_instance(instance[key], sub, refs, errors, f"{path}.{key}")
        for required in schema.get("required", []):
            if required not in instance:
                errors.append(f"{path}: missing required property {required!r}")

    if isinstance(instance, list):
        items = schema.get("items")
        if isinstance(items, dict):
            for index, item in enumerate(instance):
                _validate_instance(item, items, refs, errors, f"{path}[{index}]")
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"{path}: expected at least {schema['minItems']} items")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append(f"{path}: expected at most {schema['maxItems']} items")
        if schema.get("uniqueItems") and len(instance) != len(
            {_hashable(v) for v in instance}
        ):
            errors.append(f"{path}: items must be unique")

    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(
                f"{path}: string shorter than {schema['minLength']} chars"
            )
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append(
                f"{path}: string longer than {schema['maxLength']} chars"
            )
        if "pattern" in schema and re.search(schema["pattern"], instance) is None:
            errors.append(f"{path}: does not match pattern {schema['pattern']!r}")

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: less than minimum {schema['minimum']}")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{path}: greater than maximum {schema['maximum']}")

    if "allOf" in schema:
        for sub in schema["allOf"]:
            _validate_instance(instance, sub, refs, errors, path)
    if "anyOf" in schema:
        if not any(_is_valid(instance, sub, refs) for sub in schema["anyOf"]):
            errors.append(f"{path}: failed anyOf {schema['anyOf']!r}")
    if "oneOf" in schema:
        count = sum(1 for sub in schema["oneOf"] if _is_valid(instance, sub, refs))
        if count != 1:
            errors.append(f"{path}: failed oneOf ({count} subschemas matched)")


def _is_valid(instance: Any, schema: Dict[str, Any], refs: Dict[str, Any]) -> bool:
    """Return True when ``instance`` validates against ``schema``."""
    probe: List[str] = []
    _validate_instance(instance, schema, refs, probe, "$")
    return not probe


def validate_schema(data: Any) -> List[str]:
    """Validate a parsed trustfile document against the v1 JSON Schema.

    Returns a list of human-readable validation errors (empty when valid).
    The validator covers the keyword subset used by ``TRUSTFILE_SCHEMA_V1``
    (``type``, ``properties``, ``required``, ``items``, ``enum``, ``const``,
    ``pattern``, numeric bounds, length bounds, ``uniqueItems``, ``$ref`` and
    the ``anyOf``/``oneOf``/``allOf`` compositions).
    """
    errors: List[str] = []
    _validate_instance(data, TRUSTFILE_SCHEMA_V1, _refs(TRUSTFILE_SCHEMA_V1), errors, "trustfile")
    return errors


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class EgressRule(BaseModel):
    """A single network egress rule: a hostname or a glob pattern."""

    host: Optional[str] = None
    pattern: Optional[str] = None

    @field_validator("host", "pattern")
    @classmethod
    def _strip(cls, value: Optional[str]) -> Optional[str]:
        return value.strip() if isinstance(value, str) else value

    @model_validator(mode="after")
    def _exactly_one(self) -> "EgressRule":
        has_host = self.host is not None
        has_pattern = self.pattern is not None
        if has_host == has_pattern:
            raise ValueError(
                "an egress rule must set exactly one of 'host' or 'pattern'"
            )
        return self

    def matches(self, target: str) -> bool:
        """Return True when ``target`` matches this rule."""
        target_lower = target.lower()
        if self.host:
            return self.host.lower() == target_lower
        return fnmatch.fnmatch(target_lower, self.pattern.lower())

    def display(self) -> str:
        """Human-readable form of the rule."""
        return self.pattern or self.host or "?"


class NetworkPolicy(BaseModel):
    """Egress policy: an explicit allow list and an optional deny list."""

    allow: List[EgressRule] = Field(default_factory=list)
    deny: List[EgressRule] = Field(default_factory=list)

    def egress_allowed(self, target: str) -> bool:
        """Return True when ``target`` is permitted by the policy.

        Deny rules take precedence over allow rules.
        """
        if any(rule.matches(target) for rule in self.deny):
            return False
        if not self.allow:
            return True
        return any(rule.matches(target) for rule in self.allow)


class Mount(BaseModel):
    """A filesystem mount rule within the sandbox."""

    host_path: str
    container_path: str
    mode: Literal["read-only", "read-write", "masked"] = "read-only"

    @model_validator(mode="after")
    def _path_is_safe(self) -> "Mount":
        if not os.path.isabs(self.container_path):
            raise ValueError(
                "container_path must be absolute-style (e.g. '/data')"
            )
        parts = [p for p in self.container_path.split(os.sep) if p not in ("", ".")]
        if ".." in parts:
            raise ValueError("container_path must not contain '..'")
        return self


class ResourceCaps(BaseModel):
    """Resource caps declared by a trustfile profile."""

    cpu: float = 1.0
    mem_mb: int = 512
    disk_mb: int = 1024
    time_s: float = 30.0


class SecretRef(BaseModel):
    """A reference to a secret vault path the workload may access."""

    vault_path: str
    env: Optional[str] = None

    @field_validator("vault_path")
    @classmethod
    def _vault_path(cls, value: str) -> str:
        if not (value.startswith("vault://") or value.startswith("/secrets/")):
            raise ValueError(
                "vault_path must be 'vault://<name>' or '/secrets/<name>'"
            )
        return value


class TrustfileSpec(BaseModel):
    """A parsed trustfile v1 profile."""

    version: Literal["1"] = "1"
    name: str
    syscalls: List[str] = Field(default_factory=lambda: list(DEFAULT_SYSCALLS))
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
    mounts: List[Mount] = Field(default_factory=list)
    resources: ResourceCaps = Field(default_factory=ResourceCaps)
    secrets: List[SecretRef] = Field(default_factory=list)
    expiry: Optional[datetime] = None

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value):
            raise ValueError("name must match [A-Za-z0-9][A-Za-z0-9._-]*")
        return value

    @field_validator("expiry")
    @classmethod
    def _expiry(cls, value: Optional[datetime]) -> Optional[datetime]:
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value


# ---------------------------------------------------------------------------
# Loading / parsing
# ---------------------------------------------------------------------------


def parse_trustfile(text: str) -> TrustfileSpec:
    """Parse a trustfile.yaml document into a :class:`TrustfileSpec`.

    Raises :class:`TrustfileValidationError` with all schema/model errors.
    """
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise TrustfileValidationError([f"invalid YAML: {exc}"]) from exc

    if not isinstance(data, dict):
        raise TrustfileValidationError(["trustfile must be a YAML mapping"])

    if isinstance(data.get("version"), int) and data["version"] == 1:
        data["version"] = "1"

    errors = validate_schema(data)
    if errors:
        raise TrustfileValidationError(errors)

    try:
        return TrustfileSpec.model_validate(data)
    except ValidationError as exc:
        model_errors = [
            f"{'.'.join(str(part) for part in err['loc']) or 'trustfile'}: {err['msg']}"
            for err in exc.errors()
        ]
        raise TrustfileValidationError(model_errors) from exc


def load_trustfile(path: str) -> TrustfileSpec:
    """Load and validate a trustfile from a YAML file path."""
    with open(path, "r", encoding="utf-8") as handle:
        return parse_trustfile(handle.read())


def trustfile_digest(spec: TrustfileSpec) -> str:
    """Return the canonical sha256 digest of a trustfile profile."""
    canonical = json.dumps(
        spec.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def trustfile_to_yaml(spec: TrustfileSpec) -> str:
    """Serialize a profile to YAML for authoring or distribution."""
    data = spec.model_dump(mode="json", exclude_none=True)
    for key in ("network", "mounts", "secrets"):
        if not data.get(key):
            data.pop(key, None)
    return yaml.safe_dump(data, sort_keys=False, default_flow_style=False)


# ---------------------------------------------------------------------------
# Filesystem mount staging
# ---------------------------------------------------------------------------


def _resolve_container_path(sandbox_dir: str, container_path: str) -> str:
    """Resolve an absolute-style container path inside the sandbox jail."""
    normalized = os.path.normpath(
        os.path.join(sandbox_dir, container_path.lstrip(os.sep))
    )
    if not normalized.startswith(sandbox_dir + os.sep):
        raise ValueError(f"mount path escapes sandbox: {container_path}")
    return normalized


def _make_read_only(root: str) -> None:
    """Recursively strip write bits from a staged read-only mount."""
    if os.path.isfile(root):
        os.chmod(root, os.stat(root).st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
        return
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            try:
                os.chmod(path, os.stat(path).st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
            except OSError:
                continue


def apply_mounts(spec: TrustfileSpec, sandbox_dir: str) -> List[Dict[str, Any]]:
    """Stage the profile's filesystem mounts into the sandbox directory.

    ``read-only`` and ``read-write`` mounts copy the host path into the sandbox
    jail (read-only strips write bits); ``masked`` paths are created as empty
    placeholders so the workload cannot observe the host's contents. Mounted
    paths are visible relative to the sandbox working directory.

    Returns one result dict per mount with the ``ok`` flag and a ``detail``
    message for any failures.
    """
    results: List[Dict[str, Any]] = []
    for mount in spec.mounts:
        entry: Dict[str, Any] = {
            "host_path": mount.host_path,
            "container_path": mount.container_path,
            "mode": mount.mode,
            "staged_path": "",
            "ok": True,
            "detail": "",
        }
        try:
            staged = _resolve_container_path(sandbox_dir, mount.container_path)
            entry["staged_path"] = staged
            if mount.mode == "masked":
                os.makedirs(staged, exist_ok=True)
                results.append(entry)
                continue
            if not os.path.exists(mount.host_path):
                raise FileNotFoundError(f"host path does not exist: {mount.host_path}")
            if os.path.isdir(mount.host_path):
                os.makedirs(staged, exist_ok=True)
                shutil.copytree(mount.host_path, staged, dirs_exist_ok=True)
                if mount.mode == "read-only":
                    _make_read_only(staged)
            else:
                os.makedirs(os.path.dirname(staged), exist_ok=True)
                shutil.copy2(mount.host_path, staged)
                if mount.mode == "read-only":
                    _make_read_only(staged)
        except Exception as exc:  # noqa: BLE001 - surfaced in the receipt
            entry["ok"] = False
            entry["detail"] = str(exc)
        results.append(entry)
    return results


# ---------------------------------------------------------------------------
# Migration helper
# ---------------------------------------------------------------------------


def sandbox_config_to_trustfile(config: SandboxConfig) -> TrustfileSpec:
    """Translate a legacy :class:`SandboxConfig` into a trustfile v1 profile.

    Maps the resource knobs understood today (wall-clock timeout, memory cap,
    disk cap and optional CPU cap) onto the trustfile ``resources`` section.
    """
    return TrustfileSpec(
        name="migrated",
        resources=ResourceCaps(
            cpu=config.max_cpu_cores or 1.0,
            mem_mb=config.max_memory_mb or 1024,
            disk_mb=config.max_disk_mb or 100,
            time_s=config.max_timeout_seconds,
        ),
    )
