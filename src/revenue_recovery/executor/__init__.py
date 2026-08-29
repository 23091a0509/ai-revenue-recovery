"""Executor package for AI Revenue Recovery MVP.

Provides sandbox egress firewall, action execution abstractions, and simulator integration.
"""

from src.revenue_recovery.executor.sandbox_guard import (
    EgressVerdict,
    SandboxGuard,
    SandboxViolationError,
    validate_egress_url,
)

__all__ = [
    "EgressVerdict",
    "SandboxGuard",
    "SandboxViolationError",
    "validate_egress_url",
]
