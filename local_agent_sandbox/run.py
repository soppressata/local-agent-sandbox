"""
``sandboxctl run`` engine.

Resolves the local machine as a Sandbox Mesh node backed by the existing
``LocalAgentSandbox`` backend, enforces the trustfile profile across every
check the local backend can genuinely apply, produces a machine-readable
:class:`Receipt`, signs it with the node's Ed25519 key and appends it to the
versioned JSONL receipt store.
"""

from __future__ import annotations

import os
import platform
import shutil
import tempfile
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .core import LocalAgentSandbox, SandboxConfig, SandboxResult
from .receipt import (
    EnforcementSummary,
    NodeInfo,
    PolicyCheck,
    Receipt,
    ReceiptStore,
    SignedReceipt,
    get_or_create_signing_key,
    sign_receipt,
)
from .trustfile import (
    DEFAULT_SYSCALLS,
    TrustfileSpec,
    apply_mounts,
    trustfile_digest,
)


def _system_mem_mb() -> int:
    """Total system memory in MiB, parsed from /proc/meminfo (0 if unknown)."""
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def _dir_size_mb(path: str) -> float:
    """Recursive size of a directory (or single file) in MiB."""
    if not os.path.exists(path):
        return 0.0
    if os.path.isfile(path):
        return os.path.getsize(path) / (1024 * 1024)
    total = 0
    for dirpath, _dirnames, filenames in os.walk(path):
        for name in filenames:
            try:
                total += os.path.getsize(os.path.join(dirpath, name))
            except OSError:
                continue
    return total / (1024 * 1024)


def _truncate(text: str, limit: int = 8192) -> str:
    """Truncate command output stored in a receipt."""
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated {len(text) - limit} chars]"


class LocalNodeResolver:
    """Resolves the local machine descriptor using the local backend."""

    def resolve(self) -> NodeInfo:
        """Return the local node's capacity and backend descriptor."""
        return NodeInfo(
            id=f"local-{platform.node()}",
            hostname=platform.node(),
            platform=f"{platform.system()} {platform.release()}",
            backend="local-agent-sandbox",
            cpu_cores=os.cpu_count() or 1,
            mem_mb=_system_mem_mb(),
        )


class ProfileEnforcer:
    """Enforces a trustfile profile across the local backend's capabilities.

    Checks the local backend cannot genuinely apply (custom syscall filters,
    network egress deny rules, secret vault injection) fail closed, so a run
    only exits 0 when every declared policy dimension was fully enforced.
    """

    def __init__(self, spec: TrustfileSpec) -> None:
        self.spec = spec

    def check_expiry(self, now: Optional[datetime] = None) -> PolicyCheck:
        """Validate the profile's expiry timestamp."""
        if self.spec.expiry is None:
            return PolicyCheck(name="expiry", applied=True, ok=True, detail="no expiry set")
        now = now or datetime.now(timezone.utc)
        expired = now > self.spec.expiry
        return PolicyCheck(
            name="expiry",
            applied=True,
            ok=not expired,
            detail=f"expiry={self.spec.expiry.isoformat()} now={now.isoformat()}",
        )

    def check_resources(self, result: SandboxResult, sandbox_dir: str) -> PolicyCheck:
        """Verify the run stayed within the declared resource caps."""
        caps = self.spec.resources
        problems: List[str] = []
        if result.exit_code == 124:
            problems.append(f"wall-time cap ({caps.time_s}s) exceeded")
        if result.exit_code == 137:
            problems.append(f"memory cap ({caps.mem_mb}MB) exceeded (SIGKILL)")
        disk_used = _dir_size_mb(sandbox_dir)
        if disk_used > caps.disk_mb:
            problems.append(f"disk cap exceeded: {disk_used:.1f}MB > {caps.disk_mb}MB")
        return PolicyCheck(
            name="resources",
            applied=True,
            ok=not problems,
            detail="; ".join(problems)
            or f"within caps (time={caps.time_s}s mem={caps.mem_mb}MB disk={caps.disk_mb}MB)",
        )

    def check_guardrails(self, result: SandboxResult) -> PolicyCheck:
        """Verify the backend guardrail layer did not have to block the command."""
        if result.blocked:
            return PolicyCheck(
                name="guardrails",
                applied=True,
                ok=False,
                detail=result.block_reason or "command blocked by backend guardrails",
            )
        return PolicyCheck(name="guardrails", applied=True, ok=True, detail="no guardrail blocks")

    def check_mounts(self, mount_results: List[Dict[str, Any]]) -> PolicyCheck:
        """Verify every declared mount was staged successfully."""
        failed = [m for m in mount_results if not m.get("ok")]
        return PolicyCheck(
            name="mounts",
            applied=True,
            ok=not failed,
            detail="; ".join(f"{m.get('container_path')}: {m.get('detail')}" for m in failed)
            or f"{len(mount_results)} mount(s) staged",
        )

    def check_syscalls(self) -> PolicyCheck:
        """Verify the syscall allowlist can be enforced by the local backend."""
        if set(self.spec.syscalls) == set(DEFAULT_SYSCALLS):
            return PolicyCheck(
                name="syscalls",
                applied=True,
                ok=True,
                detail=f"default allowlist ({len(self.spec.syscalls)} syscalls) applied via local guardrail backend",
            )
        return PolicyCheck(
            name="syscalls",
            applied=False,
            ok=False,
            detail="custom syscall allowlist requires the native seccomp backend (mesh phase 3)",
        )

    def check_network(self) -> PolicyCheck:
        """Verify network egress policy can be enforced by the local backend."""
        if self.spec.network.deny:
            rules = ", ".join(rule.display() for rule in self.spec.network.deny)
            return PolicyCheck(
                name="network",
                applied=False,
                ok=False,
                detail=f"egress deny rules require the native network namespace backend (mesh phase 3): {rules}",
            )
        allows = ", ".join(rule.display() for rule in self.spec.network.allow) or "all"
        return PolicyCheck(
            name="network",
            applied=True,
            ok=True,
            detail=f"no deny rules; egress allow list recorded: {allows}",
        )

    def check_secrets(self) -> PolicyCheck:
        """Verify secret vault policy can be honored by the local backend."""
        if not self.spec.secrets:
            return PolicyCheck(name="secrets", applied=True, ok=True, detail="no secret vault paths declared")
        paths = ", ".join(secret.vault_path for secret in self.spec.secrets)
        return PolicyCheck(
            name="secrets",
            applied=False,
            ok=False,
            detail=f"secret vault injection requires a vault backend (mesh phase 4); failing closed for: {paths}",
        )

    def evaluate(
        self,
        result: SandboxResult,
        mount_results: List[Dict[str, Any]],
        sandbox_dir: str,
        now: Optional[datetime] = None,
    ) -> EnforcementSummary:
        """Run all checks and summarize whether the policy was fully enforced."""
        checks = [
            self.check_expiry(now),
            self.check_resources(result, sandbox_dir),
            self.check_guardrails(result),
            self.check_mounts(mount_results),
            self.check_syscalls(),
            self.check_network(),
            self.check_secrets(),
        ]
        return EnforcementSummary(
            checks=checks,
            fully_enforced=all(check.applied and check.ok for check in checks),
        )


class RunEngine:
    """Orchestrates a trustfile-governed run on the local node."""

    def __init__(
        self,
        node_resolver: Optional[LocalNodeResolver] = None,
        store: Optional[ReceiptStore] = None,
        keys_dir: Optional[str] = None,
        write_receipt: bool = True,
    ) -> None:
        self.node_resolver = node_resolver or LocalNodeResolver()
        self.store = store or ReceiptStore()
        self.keys_dir = keys_dir
        self.write_receipt = write_receipt

    def run(self, spec: TrustfileSpec, image: str) -> Tuple[Receipt, SignedReceipt]:
        """Execute ``image`` under ``spec``, returning the receipt and envelope.

        The command runs inside a fresh ``LocalAgentSandbox`` jail configured
        from the profile's resource caps; mounts are staged into the jail first.
        """
        node = self.node_resolver.resolve()
        config = SandboxConfig(
            max_timeout_seconds=spec.resources.time_s,
            max_memory_mb=spec.resources.mem_mb,
            max_disk_mb=spec.resources.disk_mb,
            max_cpu_cores=spec.resources.cpu,
        )

        sandbox_dir = tempfile.mkdtemp(prefix=f"trustfile_{spec.name}_")
        started_at = datetime.now(timezone.utc).isoformat()
        start_time = time.time()
        try:
            sandbox = LocalAgentSandbox(config=config, sandbox_dir=sandbox_dir)
            mount_results = apply_mounts(spec, sandbox_dir)
            result = sandbox.execute(image)
            duration_ms = (time.time() - start_time) * 1000
            finished_at = datetime.now(timezone.utc).isoformat()
            enforcement = ProfileEnforcer(spec).evaluate(result, mount_results, sandbox_dir)
            receipt = Receipt(
                id=uuid.uuid4().hex,
                trustfile=trustfile_digest(spec),
                trustfile_name=spec.name,
                image=image,
                command=image,
                node=node,
                started_at=started_at,
                finished_at=finished_at,
                duration_ms=duration_ms,
                exit_code=result.exit_code,
                blocked=result.blocked,
                block_reason=result.block_reason,
                enforcement=enforcement,
                mounts=mount_results,
                stdout=_truncate(result.stdout),
                stderr=_truncate(result.stderr),
            )
        finally:
            shutil.rmtree(sandbox_dir, ignore_errors=True)

        private_key_bytes, _public_key_bytes, _key_id = get_or_create_signing_key(self.keys_dir)
        signed = sign_receipt(receipt, private_key_bytes)
        if self.write_receipt:
            self.store.write(signed)
        return receipt, signed
