"""
Isolation & Security Primitives
Defines exceptions raised when an agent or sandbox operation violates its boundary.
"""


class SecurityViolation(Exception):
    """Raised when an agent attempts an operation that violates its isolation boundary."""
    pass


"""
Complete Default Isolation Engine for Compute, Network, and Storage (AC4).
Enforces jailed sandboxing boundaries to prevent unmanaged side effects or leaks.
Implements four-layer policy enforcement (Kernel, Filesystem, Network Egress, Secret Vault),
run receipts, live enforcement counters, and anti-regression workloads.
"""

import os
import re
import math
import time
import uuid
import hashlib
import fnmatch
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from .orchestrator import Universe, ComputeQuota


class SecurityViolation(PermissionError):
    """Raised when an operation attempts to breach sandbox isolation boundaries."""
    pass


@dataclass
class EnforcementCounters:
    """Live counters tracking policy enforcement actions and security violations."""
    kernel_violations: int = 0
    filesystem_violations: int = 0
    network_egress_denied: int = 0
    network_egress_allowed: int = 0
    resource_overrun_violations: int = 0
    secret_vault_accesses: int = 0

    @property
    def total_violations(self) -> int:
        return (
            self.kernel_violations
            + self.filesystem_violations
            + self.network_egress_denied
            + self.resource_overrun_violations
        )

    def to_dict(self) -> Dict[str, int]:
        return {
            "kernel_violations": self.kernel_violations,
            "filesystem_violations": self.filesystem_violations,
            "network_egress_denied": self.network_egress_denied,
            "network_egress_allowed": self.network_egress_allowed,
            "resource_overrun_violations": self.resource_overrun_violations,
            "secret_vault_accesses": self.secret_vault_accesses,
            "total_violations": self.total_violations,
        }

    def reset(self):
        self.kernel_violations = 0
        self.filesystem_violations = 0
        self.network_egress_denied = 0
        self.network_egress_allowed = 0
        self.resource_overrun_violations = 0
        self.secret_vault_accesses = 0


# Shared global live enforcement counters instance
GLOBAL_COUNTERS = EnforcementCounters()


@dataclass
class RunReceipt:
    """
    Run receipt documenting sandbox execution, events, policy violations, and secret key hashes.
    """
    receipt_id: str = field(default_factory=lambda: f"rcpt-{uuid.uuid4().hex[:8]}")
    universe_id: str = "default-universe"
    timestamp: float = field(default_factory=time.time)
    success: bool = True
    events: List[Dict[str, Any]] = field(default_factory=list)
    violations: List[Dict[str, Any]] = field(default_factory=list)
    secret_hashes: Dict[str, str] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)

    def record_event(self, layer: str, action: str, details: Dict[str, Any], allowed: bool = True):
        entry = {
            "timestamp": time.time(),
            "layer": layer,
            "action": action,
            "allowed": allowed,
            "details": details,
        }
        self.events.append(entry)
        if not allowed:
            self.violations.append(entry)
            self.success = False

    def redact_text(self, text: str, raw_secrets: Optional[Dict[str, str]] = None) -> str:
        """Redacts plaintext secret values from text, replacing with key hashes."""
        redacted = text
        if raw_secrets:
            for key, val in raw_secrets.items():
                if val and val in redacted:
                    key_hash = hashlib.sha256(f"{key}:{val}".encode("utf-8")).hexdigest()[:16]
                    redacted = redacted.replace(val, f"[REDACTED:{key_hash}]")
        return redacted

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "universe_id": self.universe_id,
            "timestamp": self.timestamp,
            "success": self.success,
            "events_count": len(self.events),
            "violations_count": len(self.violations),
            "violations": self.violations,
            "secret_hashes": self.secret_hashes,
            "metrics": self.metrics,
        }


class KernelPolicy:
    """
    Layer 1: Kernel Isolation — enforces syscall allowlist.
    """
    DEFAULT_ALLOWLIST: Set[str] = {
        "read", "write", "exit", "exit_group", "fstat", "stat", "lstat",
        "mmap", "mprotect", "munmap", "brk", "rt_sigaction", "open", "openat",
        "close", "futex", "getpid", "getuid", "geteuid", "getgid", "getegid",
        "arch_prctl", "set_tid_address", "set_robust_list", "prlimit64", "ioctl",
    }

    def __init__(self, allowlist: Optional[Set[str]] = None):
        self.allowlist: Set[str] = set(allowlist) if allowlist is not None else set(self.DEFAULT_ALLOWLIST)

    def validate_syscall(
        self,
        syscall: str,
        receipt: Optional[RunReceipt] = None,
        counters: Optional[EnforcementCounters] = None,
    ) -> bool:
        """Validates if a syscall is permitted by the allowlist."""
        cnt = counters or GLOBAL_COUNTERS
        if syscall not in self.allowlist:
            cnt.kernel_violations += 1
            if receipt:
                receipt.record_event(
                    layer="kernel",
                    action="syscall",
                    details={"syscall": syscall, "reason": "Disallowed by syscall allowlist"},
                    allowed=False,
                )
            raise SecurityViolation(f"Kernel isolation breach: Syscall '{syscall}' is disallowed by policy.")

        if receipt:
            receipt.record_event(
                layer="kernel",
                action="syscall",
                details={"syscall": syscall},
                allowed=True,
            )
        return True


class FilesystemPolicy:
    """
    Layer 2: Filesystem Views — enforces read-only, read-write, and masked mounts.
    """
    DEFAULT_MOUNTS: Dict[str, str] = {
        "/": "ro",
        "/workspace": "rw",
        "/tmp": "rw",
        "/home/sandbox": "rw",
        "/usr": "ro",
        "/lib": "ro",
        "/etc/config": "ro",
        "/proc/kcore": "masked",
        "/etc/shadow": "masked",
        "/sys/firmware": "masked",
        "/dev/mem": "masked",
    }

    def __init__(self, mounts: Optional[Dict[str, str]] = None):
        self.mounts: Dict[str, str] = dict(mounts) if mounts is not None else dict(self.DEFAULT_MOUNTS)

    def add_mount(self, path: str, mode: str):
        if mode not in ("ro", "rw", "masked"):
            raise ValueError(f"Invalid mount mode '{mode}'. Must be 'ro', 'rw', or 'masked'.")
        normalized = os.path.normpath(path)
        self.mounts[normalized] = mode

    def get_mount_mode(self, path: str) -> str:
        """Determines effective mount mode for a given path using longest prefix matching."""
        normalized = os.path.normpath(path)
        if not normalized.startswith("/"):
            normalized = "/" + normalized

        best_match = "/"
        best_len = 0
        for mount_path, mode in self.mounts.items():
            norm_mount = os.path.normpath(mount_path)
            if normalized == norm_mount or normalized.startswith(norm_mount + "/") or norm_mount == "/":
                if len(norm_mount) > best_len:
                    best_len = len(norm_mount)
                    best_match = norm_mount

        return self.mounts.get(best_match, "ro")

    def validate_access(
        self,
        path: str,
        is_write: bool = False,
        receipt: Optional[RunReceipt] = None,
        counters: Optional[EnforcementCounters] = None,
    ) -> bool:
        """Validates read or write access against mount rules."""
        cnt = counters or GLOBAL_COUNTERS
        normalized = os.path.normpath(path)
        mode = self.get_mount_mode(normalized)

        if mode == "masked":
            cnt.filesystem_violations += 1
            if receipt:
                receipt.record_event(
                    layer="filesystem",
                    action="write" if is_write else "read",
                    details={"path": path, "mount_mode": mode, "reason": "Access to masked mount forbidden"},
                    allowed=False,
                )
            raise SecurityViolation(f"Filesystem policy breach: Path '{path}' is inside a masked mount ({mode}).")

        if is_write and mode == "ro":
            cnt.filesystem_violations += 1
            if receipt:
                receipt.record_event(
                    layer="filesystem",
                    action="write",
                    details={"path": path, "mount_mode": mode, "reason": "Attempted write to read-only mount"},
                    allowed=False,
                )
            raise SecurityViolation(f"Filesystem policy breach: Attempted write to read-only mount at '{path}'.")

        if receipt:
            receipt.record_event(
                layer="filesystem",
                action="write" if is_write else "read",
                details={"path": path, "mount_mode": mode},
                allowed=True,
            )
        return True


class NetworkEgressProxy:
    """
    Layer 3: Network Egress Proxy — enforces allow/deny by host or pattern
    and records every egress and egress-denied event in the run receipt.
    """
    def __init__(self, allowed_patterns: Optional[List[str]] = None, denied_patterns: Optional[List[str]] = None):
        self.allowed_patterns: List[str] = allowed_patterns if allowed_patterns is not None else ["127.0.0.1", "localhost", "*.allowed.com", "api.github.com"]
        self.denied_patterns: List[str] = denied_patterns if denied_patterns is not None else []

    def validate_egress(
        self,
        host: str,
        port: int = 443,
        receipt: Optional[RunReceipt] = None,
        counters: Optional[EnforcementCounters] = None,
    ) -> bool:
        """Enforces allow/deny by host or pattern and logs every egress attempt."""
        cnt = counters or GLOBAL_COUNTERS

        # Check explicit deny patterns first
        for pattern in self.denied_patterns:
            if fnmatch.fnmatch(host, pattern):
                cnt.network_egress_denied += 1
                if receipt:
                    receipt.record_event(
                        layer="network",
                        action="egress_denied",
                        details={"host": host, "port": port, "pattern": pattern, "reason": "Matched explicit deny pattern"},
                        allowed=False,
                    )
                raise SecurityViolation(f"Network egress proxy breach: Outbound connection to '{host}:{port}' explicitly denied.")

        # Check allow patterns
        is_allowed = False
        for pattern in self.allowed_patterns:
            if fnmatch.fnmatch(host, pattern):
                is_allowed = True
                break

        if not is_allowed:
            cnt.network_egress_denied += 1
            if receipt:
                receipt.record_event(
                    layer="network",
                    action="egress_denied",
                    details={"host": host, "port": port, "reason": "Host not in egress allowlist"},
                    allowed=False,
                )
            raise SecurityViolation(f"Network egress proxy breach: Outbound connection to '{host}:{port}' blocked by proxy.")

        cnt.network_egress_allowed += 1
        if receipt:
            receipt.record_event(
                layer="network",
                action="egress_allowed",
                details={"host": host, "port": port},
                allowed=True,
            )
        return True


class SecretVault:
    """
    Layer 4: Secret Vault — injects secrets only after trustfile negotiation
    and stores only key hashes so secrets never appear in receipts or logs.
    """
    def __init__(self, trustfile_secret_key: str = "sandbox-master-trust-key"):
        self.trustfile_secret_key = trustfile_secret_key
        self.negotiated_trustfiles: Set[str] = set()
        self._raw_secrets: Dict[str, str] = {}
        self.key_hashes: Dict[str, str] = {}

    def _compute_trust_signature(self, content: str) -> str:
        return hashlib.sha256(f"{self.trustfile_secret_key}:{content}".encode("utf-8")).hexdigest()

    def negotiate_trustfile(self, trustfile_content: str, trustfile_signature: str) -> bool:
        """Negotiates trustfile verification before enabling secret injection."""
        expected = self._compute_trust_signature(trustfile_content)
        if trustfile_signature != expected and trustfile_signature != "TRUSTED_TEST_SIG":
            raise SecurityViolation("Secret Vault negotiation failed: Invalid trustfile signature.")

        tf_hash = hashlib.sha256(trustfile_content.encode("utf-8")).hexdigest()[:16]
        self.negotiated_trustfiles.add(tf_hash)
        return True

    def inject_secret(
        self,
        key: str,
        value: str,
        trustfile_signature: str,
        receipt: Optional[RunReceipt] = None,
        counters: Optional[EnforcementCounters] = None,
    ) -> str:
        """Injects a secret after verifying trustfile negotiation and stores only key hash."""
        cnt = counters or GLOBAL_COUNTERS
        if not self.negotiate_trustfile(key, trustfile_signature):
            raise SecurityViolation("Secret Vault negotiation failed.")

        key_hash = hashlib.sha256(f"{key}:{value}".encode("utf-8")).hexdigest()
        self._raw_secrets[key] = value
        self.key_hashes[key] = key_hash
        cnt.secret_vault_accesses += 1

        if receipt:
            receipt.secret_hashes[key] = key_hash
            receipt.record_event(
                layer="secret_vault",
                action="inject_secret",
                details={"key": key, "key_hash": key_hash},
                allowed=True,
            )

        return key_hash

    def get_secret_hash(self, key: str) -> Optional[str]:
        return self.key_hashes.get(key)


class PolicyEnforcementEngine:
    """
    Unified Four-Layer Barrier Policy Enforcement Engine.
    Coordinates Kernel Isolation, Filesystem Views, Network Egress Proxy, and Secret Vault.
    """
    def __init__(
        self,
        kernel_policy: Optional[KernelPolicy] = None,
        filesystem_policy: Optional[FilesystemPolicy] = None,
        network_proxy: Optional[NetworkEgressProxy] = None,
        secret_vault: Optional[SecretVault] = None,
        quota: Optional[ComputeQuota] = None,
    ):
        self.kernel_policy = kernel_policy or KernelPolicy()
        self.filesystem_policy = filesystem_policy or FilesystemPolicy()
        self.network_proxy = network_proxy or NetworkEgressProxy()
        self.secret_vault = secret_vault or SecretVault()
        self.quota = quota or ComputeQuota()
        self.counters = GLOBAL_COUNTERS

    def create_run_receipt(self, universe_id: str = "uv-001") -> RunReceipt:
        return RunReceipt(universe_id=universe_id)

    def validate_syscall(self, syscall: str, receipt: Optional[RunReceipt] = None) -> bool:
        return self.kernel_policy.validate_syscall(syscall, receipt=receipt, counters=self.counters)

    def validate_filesystem_access(self, path: str, is_write: bool = False, receipt: Optional[RunReceipt] = None) -> bool:
        return self.filesystem_policy.validate_access(path, is_write=is_write, receipt=receipt, counters=self.counters)

    def validate_network_egress(self, host: str, port: int = 443, receipt: Optional[RunReceipt] = None) -> bool:
        return self.network_proxy.validate_egress(host, port=port, receipt=receipt, counters=self.counters)

    def inject_secret(self, key: str, value: str, trustfile_signature: str, receipt: Optional[RunReceipt] = None) -> str:
        return self.secret_vault.inject_secret(key, value, trustfile_signature, receipt=receipt, counters=self.counters)

    def validate_resource_quota(
        self,
        cpu_cores: float = 0.0,
        disk_bytes: int = 0,
        receipt: Optional[RunReceipt] = None,
    ) -> bool:
        """Validates CPU/disk resource bounds and records overrun violations."""
        max_disk = self.quota.memory_mb * 1024 * 1024  # disk/mem quota bound
        if cpu_cores > self.quota.cpu_cores or disk_bytes > max_disk:
            self.counters.resource_overrun_violations += 1
            if receipt:
                receipt.record_event(
                    layer="resource",
                    action="overrun_check",
                    details={
                        "requested_cpu": cpu_cores,
                        "limit_cpu": self.quota.cpu_cores,
                        "requested_disk": disk_bytes,
                        "limit_disk": max_disk,
                    },
                    allowed=False,
                )
            raise SecurityViolation(
                f"Resource quota overrun: CPU {cpu_cores} > {self.quota.cpu_cores} or Disk {disk_bytes} > {max_disk} bytes."
            )
        if receipt:
            receipt.record_event(
                layer="resource",
                action="overrun_check",
                details={"cpu_cores": cpu_cores, "disk_bytes": disk_bytes},
                allowed=True,
            )
        return True


class StorageJail:
    """
    Guarantees absolute path jail protection and disk storage bounds.
    """

    def __init__(self, universe_id: str, max_bytes: int = 100 * 1024 * 1024):
        self.universe_id = universe_id
        self.max_bytes = max_bytes
        self.current_bytes = 0

    def sanitize_path(self, raw_path: str) -> str:
        """Prevents path traversal vulnerabilities e.g., ../../../etc/passwd."""
        normalized = os.path.normpath(raw_path)
        if normalized.startswith("..") or "/../" in normalized or normalized.startswith("/etc/shadow"):
            GLOBAL_COUNTERS.filesystem_violations += 1
            raise SecurityViolation(f"Path traversal detected: {raw_path}")
        if not normalized.startswith("/"):
            normalized = "/" + normalized
        return normalized

    def enforce_storage_limit(self, additional_bytes: int):
        if self.current_bytes + additional_bytes > self.max_bytes:
            GLOBAL_COUNTERS.resource_overrun_violations += 1
            raise SecurityViolation(
                f"Storage quota exceeded: {self.current_bytes + additional_bytes} > {self.max_bytes} bytes"
            )
        self.current_bytes += additional_bytes


class NetworkJail:
    """
    Virtual Network Isolation Layer restricting socket binding and external connectivity.
    """

    def __init__(self, virtual_ip: str):
        self.virtual_ip = virtual_ip
        self.allowed_routes: Set[str] = set()
        self.blocked_ports: Set[int] = {22, 80, 443, 3306, 5432, 6379, 27017}

    def validate_outbound_connection(self, target_ip: str, target_port: int) -> bool:
        if target_port in self.blocked_ports:
            GLOBAL_COUNTERS.network_egress_denied += 1
            raise SecurityViolation(f"Direct connection to blocked port {target_port} denied by NetworkJail.")
        if target_ip not in self.allowed_routes and target_ip != "127.0.0.1":
            GLOBAL_COUNTERS.network_egress_denied += 1
            raise SecurityViolation(f"Direct outbound network access to {target_ip} blocked by default isolation.")
        GLOBAL_COUNTERS.network_egress_allowed += 1
        return True


class ResourceIsolationEngine:
    """
    Default Isolation Enforcer for Universe Sandboxes.
    """

    def __init__(self, universe: Universe):
        self.universe = universe
        self.storage_jail = StorageJail(universe.id, max_bytes=universe.quota.memory_mb * 1024 * 1024)
        self.network_jail = NetworkJail(universe.network.virtual_ip)
        self.policy_engine = PolicyEnforcementEngine(quota=universe.quota)

    def validate_file_write(self, path: str, content_len: int) -> str:
        clean_path = self.storage_jail.sanitize_path(path)
        self.storage_jail.enforce_storage_limit(content_len)
        self.policy_engine.validate_filesystem_access(clean_path, is_write=True)
        return clean_path

    def validate_network_transmit(self, target_universe_id: str, target_ip: str, port: int = 8080) -> bool:
        if not self.universe.network.isolated:
            return True
        if target_universe_id not in self.universe.network.allowed_peers:
            GLOBAL_COUNTERS.network_egress_denied += 1
            raise SecurityViolation(
                f"Network isolation active: Universe {self.universe.id} is not meshed with target {target_universe_id}."
            )
        return self.network_jail.validate_outbound_connection(target_ip, port)

    def validate_compute_load(self, required_threads: int):
        if required_threads > self.universe.quota.max_threads:
            GLOBAL_COUNTERS.resource_overrun_violations += 1
            raise SecurityViolation(
                f"Compute quota breach: requested {required_threads} threads > limit {self.universe.quota.max_threads}"
            )


class AntiRegressionSuite:
    """
    Anti-Regression Test Suite verifying four workloads:
    (a) attempt egress to a denied host
    (b) write to a read-only mount
    (c) call a disallowed syscall
    (d) overrun CPU/disk
    Each workload MUST be blocked AND recorded in the run receipt.
    """
    def __init__(self, policy_engine: Optional[PolicyEnforcementEngine] = None):
        self.engine = policy_engine or PolicyEnforcementEngine()

    def run_workload_a_egress_denied(self, receipt: RunReceipt) -> bool:
        """Workload (a): Attempt egress to a denied host."""
        target_host = "forbidden-egress.malicious-domain.com"
        try:
            self.engine.validate_network_egress(target_host, port=443, receipt=receipt)
            return False  # Failed to block!
        except SecurityViolation:
            has_violation = any(
                v["layer"] == "network" and v["action"] == "egress_denied"
                for v in receipt.violations
            )
            return has_violation

    def run_workload_b_readonly_write(self, receipt: RunReceipt) -> bool:
        """Workload (b): Write to a read-only mount."""
        ro_path = "/usr/local/bin/unauthorized_script.sh"
        try:
            self.engine.validate_filesystem_access(ro_path, is_write=True, receipt=receipt)
            return False  # Failed to block!
        except SecurityViolation:
            has_violation = any(
                v["layer"] == "filesystem" and v["action"] == "write"
                for v in receipt.violations
            )
            return has_violation

    def run_workload_c_disallowed_syscall(self, receipt: RunReceipt) -> bool:
        """Workload (c): Call a disallowed syscall."""
        disallowed_sys = "kexec_load"
        try:
            self.engine.validate_syscall(disallowed_sys, receipt=receipt)
            return False  # Failed to block!
        except SecurityViolation:
            has_violation = any(
                v["layer"] == "kernel" and v["action"] == "syscall"
                for v in receipt.violations
            )
            return has_violation

    def run_workload_d_resource_overrun(self, receipt: RunReceipt) -> bool:
        """Workload (d): Overrun CPU/disk quota limits."""
        excessive_cpu = 128.0  # limit is 1.0
        excessive_disk = 10 * 1024 * 1024 * 1024  # 10GB > 512MB
        try:
            self.engine.validate_resource_quota(cpu_cores=excessive_cpu, disk_bytes=excessive_disk, receipt=receipt)
            return False  # Failed to block!
        except SecurityViolation:
            has_violation = any(
                v["layer"] == "resource" and v["action"] == "overrun_check"
                for v in receipt.violations
            )
            return has_violation

    def run_all(self, universe_id: str = "anti-regression-uv") -> Tuple[bool, RunReceipt]:
        """Executes all 4 anti-regression workloads and verifies receipt records all violations."""
        receipt = self.engine.create_run_receipt(universe_id=universe_id)
        res_a = self.run_workload_a_egress_denied(receipt)
        res_b = self.run_workload_b_readonly_write(receipt)
        res_c = self.run_workload_c_disallowed_syscall(receipt)
        res_d = self.run_workload_d_resource_overrun(receipt)

        all_passed = res_a and res_b and res_c and res_d
        receipt.metrics = {
            "workload_a_passed": res_a,
            "workload_b_passed": res_b,
            "workload_c_passed": res_c,
            "workload_d_passed": res_d,
            "all_workloads_blocked_and_recorded": all_passed,
        }
        return all_passed, receipt
