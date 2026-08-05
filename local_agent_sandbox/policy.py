"""
LocalAgentSandbox RMBR Memory & Policy Engine
Optionally indexes security policy violations and disallowed execution patterns locally using rmbr.
"""

from typing import List, Optional

try:
    import rmbr
    RMBR_AVAILABLE = True
except ImportError:
    RMBR_AVAILABLE = False


class PolicyMemoryEngine:
    """Optional rmbr-powered security memory policy indexer."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled and RMBR_AVAILABLE

    def record_violation(self, command: str, reason: str):
        """Index a security violation into local rmbr memory."""
        if not self.enabled:
            return
        try:
            rmbr.store(
                key=f"violation:{hash(command)}",
                content=f"Security Violation: '{command}' | Reason: {reason}"
            )
        except Exception:
            pass

    def search_policy_violations(self, query: str) -> List[str]:
        """Search local rmbr memory for historical policy violations."""
        if not self.enabled:
            return []
        try:
            results = rmbr.search(query)
            return [str(r) for r in results]
        except Exception:
            return []
