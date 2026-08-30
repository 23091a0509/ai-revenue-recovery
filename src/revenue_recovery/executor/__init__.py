"""Executor package for AI Revenue Recovery MVP.

Provides sandbox egress firewall, authoritative idempotent action executor, and simulator integrations.
"""

from src.revenue_recovery.executor.executor import (
    ActionExecutor,
    SandboxActionHandler,
)
from src.revenue_recovery.executor.idempotency import (
    ExecutionRequest,
    ExecutionResult,
    IdempotencyConflictError,
    IdempotencyStore,
)
from src.revenue_recovery.executor.sandbox_guard import (
    EgressVerdict,
    SandboxGuard,
    SandboxViolationError,
    validate_egress_url,
)
from src.revenue_recovery.executor.simulators import (
    MessagingSimulationResult,
    MockMessagingSimulator,
    MockPaymentSimulator,
    PaymentSimulationResult,
    create_sandbox_action_handler,
)

__all__ = [
    "ActionExecutor",
    "ExecutionRequest",
    "ExecutionResult",
    "IdempotencyConflictError",
    "IdempotencyStore",
    "SandboxActionHandler",
    "EgressVerdict",
    "SandboxGuard",
    "SandboxViolationError",
    "validate_egress_url",
    "MessagingSimulationResult",
    "MockMessagingSimulator",
    "MockPaymentSimulator",
    "PaymentSimulationResult",
    "create_sandbox_action_handler",
]
