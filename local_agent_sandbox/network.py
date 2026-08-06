"""
Network module for OpenHarness.
Provides core functionality for the network subsystem.
"""
from typing import List, Optional
from .isolation import NetworkEgressProxy, NetworkJail, SecurityViolation


def isolate_network(
    allowed_patterns: Optional[List[str]] = None,
    denied_patterns: Optional[List[str]] = None,
) -> NetworkEgressProxy:
    """Create and return a configured NetworkEgressProxy."""
    return NetworkEgressProxy(allowed_patterns=allowed_patterns, denied_patterns=denied_patterns)

