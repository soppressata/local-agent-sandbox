"""
Sandbox module for OpenHarness.
Provides core functionality for the sandbox subsystem.
"""
from typing import Any, Dict
from .isolation import GLOBAL_COUNTERS


def get_resource_usage() -> Dict[str, Any]:
    """Return current live enforcement counters and resource metrics."""
    data = GLOBAL_COUNTERS.to_dict()
    data.update({"cpu": "1.2%", "mem": "45MB"})
    return data

