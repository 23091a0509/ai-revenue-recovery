"""Executor package for AI Revenue Recovery MVP.

Provides sandbox egress firewall, authoritative idempotent action executor, and simulator integrations.
"""

from src.revenue_recovery.executor.executor import (
    ActionExecutor,
    ExecutionResult,
    IdempotencyConflictError,
    IdempotencyStore,
    SandboxActionHandler,
)
from src.revenue_recovery.executor.sandbox_guard import (
    EgressVerdict,
    SandboxGuard,
    SandboxViolationError,
    validate_egress_url,
)

__all__ = [
    "ActionExecutor",
    "ExecutionResult",
    "IdempotencyConflictError",
    "IdempotencyStore",
    "SandboxActionHandler",
    "EgressVerdict",
    "SandboxGuard",
    "SandboxViolationError",
    "validate_egress_url",
]
