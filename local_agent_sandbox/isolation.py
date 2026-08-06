"""
Isolation & Security Primitives
Defines exceptions raised when an agent or sandbox operation violates its boundary.
"""


class SecurityViolation(Exception):
    """Raised when an agent attempts an operation that violates its isolation boundary."""
    pass
