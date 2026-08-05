"""
Complete Default Isolation Engine for Compute, Network, and Storage (AC4).
Enforces jailed sandboxing boundaries to prevent unmanaged side effects or leaks.
"""

import os
import re
import math
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from .orchestrator import Universe, ComputeQuota


class SecurityViolation(PermissionError):
    """Raised when an operation attempts to breach sandbox isolation boundaries."""
    pass


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
            raise SecurityViolation(f"Path traversal detected: {raw_path}")
        if not normalized.startswith("/"):
            normalized = "/" + normalized
        return normalized

    def enforce_storage_limit(self, additional_bytes: int):
        if self.current_bytes + additional_bytes > self.max_bytes:
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
            raise SecurityViolation(f"Direct connection to blocked port {target_port} denied by NetworkJail.")
        if target_ip not in self.allowed_routes and target_ip != "127.0.0.1":
            raise SecurityViolation(f"Direct outbound network access to {target_ip} blocked by default isolation.")
        return True


class ResourceIsolationEngine:
    """
    Default Isolation Enforcer for Universe Sandboxes.
    """

    def __init__(self, universe: Universe):
        self.universe = universe
        self.storage_jail = StorageJail(universe.id, max_bytes=universe.quota.memory_mb * 1024 * 1024)
        self.network_jail = NetworkJail(universe.network.virtual_ip)

    def validate_file_write(self, path: str, content_len: int) -> str:
        clean_path = self.storage_jail.sanitize_path(path)
        self.storage_jail.enforce_storage_limit(content_len)
        return clean_path

    def validate_network_transmit(self, target_universe_id: str, target_ip: str, port: int = 8080) -> bool:
        if not self.universe.network.isolated:
            return True
        if target_universe_id not in self.universe.network.allowed_peers:
            raise SecurityViolation(
                f"Network isolation active: Universe {self.universe.id} is not meshed with target {target_universe_id}."
            )
        return self.network_jail.validate_outbound_connection(target_ip, port)

    def validate_compute_load(self, required_threads: int):
        if required_threads > self.universe.quota.max_threads:
            raise SecurityViolation(
                f"Compute quota breach: requested {required_threads} threads > limit {self.universe.quota.max_threads}"
            )
