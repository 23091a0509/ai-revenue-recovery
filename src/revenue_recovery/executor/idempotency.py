"""Idempotency store and conflict management for AI Revenue Recovery MVP.

Architecture Baseline: Frozen Architecture Baseline v11.
Target Location for Invariant INV-16:
Enforces unique idempotency keys across authorizations and executions,
preventing duplicate side-effects on retries and rejecting conflicting payloads.
"""

from datetime import datetime, timezone
import threading
from typing import Any, Dict, Optional

from src.revenue_recovery.foundation.events import (
    ActionChannel,
    ActionType,
    ExecutionStatus,
    ImmutableBaseModel,
)


class IdempotencyConflictError(ValueError):
    """Raised when an idempotency key is reused with mismatched / conflicting parameters."""
    pass


class ExecutionRequest(ImmutableBaseModel):
    """
    Authoritative independent execution request submitted to the ActionExecutor.
    Contains all independent context that must be authenticated and bounded by the ActionAuthorization token.
    """
    case_id: str
    customer_id: str
    action_type: ActionType
    channel: ActionChannel
    amount_in_cents: int
    currency: str = "INR"
    destination_url: str
    idempotency_key: str
    action_payload: Dict[str, Any] = {}


class ExecutionResult(ImmutableBaseModel):
    """Immutable outcome of an action execution."""
    idempotency_key: str
    case_id: str
    customer_id: str
    action_type: ActionType
    channel: ActionChannel
    amount_in_cents: int
    currency: str
    destination_url: str
    status: ExecutionStatus
    response_payload: Dict[str, Any] = {}
    error_message: Optional[str] = None
    executed_at: datetime = datetime.now(timezone.utc)

    def matches_request(self, request: ExecutionRequest) -> bool:
        """Verifies whether an execution request strictly matches this recorded result."""
        return (
            self.idempotency_key == request.idempotency_key
            and self.case_id == request.case_id
            and self.customer_id == request.customer_id
            and self.action_type == request.action_type
            and self.channel == request.channel
            and self.amount_in_cents == request.amount_in_cents
            and self.currency.upper() == request.currency.upper()
            and self.destination_url == request.destination_url
        )


class IdempotencyStore:
    """Thread-safe in-memory idempotency store preventing duplicate side-effects."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: Dict[str, ExecutionResult] = {}

    def get(self, idempotency_key: str) -> Optional[ExecutionResult]:
        with self._lock:
            return self._records.get(idempotency_key)

    def record(self, result: ExecutionResult) -> None:
        with self._lock:
            self._records[result.idempotency_key] = result

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
