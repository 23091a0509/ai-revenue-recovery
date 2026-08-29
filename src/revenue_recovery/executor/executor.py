"""Authoritative Action Executor for AI Revenue Recovery MVP.

Architecture Baseline: Frozen Architecture Baseline v11.
Enforces:
- INV-03: Capability-based Action Authorization
- INV-04: Executor acts ONLY on valid signed token
- INV-05: Strict MVP Sandbox Isolation (via integrated SandboxGuard)
"""

from datetime import datetime, timezone
import hashlib
import json
import threading
from typing import Any, Callable, Dict, Optional
from pydantic import BaseModel, Field

from src.revenue_recovery.foundation.audit import CryptographicAuditLogger
from src.revenue_recovery.foundation.events import (
    ActionChannel,
    ActionType,
    ExecutionStatus,
    ImmutableBaseModel,
)
from src.revenue_recovery.safety.authorizer import (
    ActionAuthorization,
    AuthorizationVerificationError,
    CryptographicAuthorizer,
)
from src.revenue_recovery.safety.circuit_breaker import (
    CapacityExceededError,
    CapacityGovernor,
    CircuitBrokenError,
    GranularCircuitBreakerRegistry,
)
from src.revenue_recovery.safety.kill_switch import (
    KillSwitchActiveError,
    KillSwitchManager,
)
from src.revenue_recovery.executor.sandbox_guard import (
    SandboxGuard,
    SandboxViolationError,
)


class IdempotencyConflictError(ValueError):
    """Raised when an idempotency key is reused with mismatched / conflicting parameters."""
    pass


class ExecutionResult(ImmutableBaseModel):
    """Immutable outcome of an action execution."""
    idempotency_key: str
    case_id: str
    action_type: ActionType
    channel: ActionChannel
    amount_in_cents: int
    destination_url: str
    status: ExecutionStatus
    response_payload: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IdempotencyStore:
    """Thread-safe in-memory idempotency store preventing duplicate side-effects."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: Dict[str, ExecutionResult] = {}
        self._in_flight: Dict[str, threading.Event] = {}

    def get(self, idempotency_key: str) -> Optional[ExecutionResult]:
        with self._lock:
            return self._records.get(idempotency_key)

    def record(self, result: ExecutionResult) -> None:
        with self._lock:
            self._records[result.idempotency_key] = result

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
            self._in_flight.clear()


# Type alias for sandbox execution handler: (channel, destination_url, payload) -> Dict[str, Any]
SandboxActionHandler = Callable[[ActionChannel, str, Dict[str, Any]], Dict[str, Any]]


def _default_sandbox_handler(channel: ActionChannel, destination_url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Default local sandbox simulator handler."""
    return {
        "status": "SUCCESS",
        "channel": str(channel),
        "destination_url": destination_url,
        "payload": payload,
        "simulator_response": "Simulated mock response 200 OK",
    }


class ActionExecutor:
    """
    Authoritative Action Executor.
    Guarantees that actions are executed ONLY if authorized by a valid cryptographically
    signed ActionAuthorization token and passed through all safety gates, egress firewalls,
    idempotency controls, and audit logs.
    """

    def __init__(
        self,
        authorizer: CryptographicAuthorizer,
        kill_switch: KillSwitchManager,
        circuit_breakers: GranularCircuitBreakerRegistry,
        capacity_governor: CapacityGovernor,
        sandbox_guard: SandboxGuard,
        audit_logger: CryptographicAuditLogger,
        idempotency_store: Optional[IdempotencyStore] = None,
        sandbox_handler: Optional[SandboxActionHandler] = None,
    ) -> None:
        self._authorizer = authorizer
        self._kill_switch = kill_switch
        self._circuit_breakers = circuit_breakers
        self._capacity_governor = capacity_governor
        self._sandbox_guard = sandbox_guard
        self._audit_logger = audit_logger
        self._idempotency_store = idempotency_store or IdempotencyStore()
        self._sandbox_handler = sandbox_handler or _default_sandbox_handler
        self._execution_lock = threading.RLock()

    def execute_action(
        self,
        token: ActionAuthorization,
        requested_amount_in_cents: int,
        destination_url: str,
        action_payload: Optional[Dict[str, Any]] = None,
        current_time: Optional[datetime] = None,
    ) -> ExecutionResult:
        """
        Executes a recovery action under strict 8-step short-circuit safety enforcement:
        1. Token verification (Cryptographic signature, TTL, bounds, channel)
        2. Idempotency pre-check (replay return or conflict detection)
        3. Kill switch gate (Global, Channel, Action, Customer, Case)
        4. Circuit breaker gate (State check and half-open probe reservation)
        5. Capacity governor gate (Count and monetary volume rate limits)
        6. Sandbox egress firewall (Scheme, Userinfo, Domain, IP, DNS rebinding)
        7. Action dispatch to Sandbox simulator
        8. Audit logging and Idempotency store commit
        """
        now = current_time or datetime.now(timezone.utc)
        payload = action_payload or {}

        # ---------------------------------------------------------------------
        # GATE 1: Cryptographic Authorization Verification
        # ---------------------------------------------------------------------
        self._authorizer.verify_authorization(
            token=token,
            expected_customer_id=token.customer_id,
            expected_currency=token.currency,
            requested_amount_in_cents=requested_amount_in_cents,
            expected_channel=token.channel,
            current_time=now,
        )

        with self._execution_lock:
            # -----------------------------------------------------------------
            # GATE 2: Idempotency Pre-Check
            # -----------------------------------------------------------------
            existing_record = self._idempotency_store.get(token.idempotency_key)
            if existing_record is not None:
                # Validate exact parameter match
                if (
                    existing_record.case_id != token.case_id
                    or existing_record.action_type != token.action_type
                    or existing_record.channel != token.channel
                    or existing_record.amount_in_cents != requested_amount_in_cents
                    or existing_record.destination_url != destination_url
                ):
                    raise IdempotencyConflictError(
                        f"Idempotency key '{token.idempotency_key}' was already processed with different parameters. "
                        "Conflicting re-execution rejected."
                    )
                # Idempotent replay: return existing result without re-executing
                return existing_record

            # -----------------------------------------------------------------
            # GATE 3: Kill Switch Gate
            # -----------------------------------------------------------------
            self._kill_switch.check_execution_allowed(
                action_type=token.action_type,
                channel=token.channel,
                customer_id=token.customer_id,
                case_id=token.case_id,
            )

            # -----------------------------------------------------------------
            # GATE 4: Circuit Breaker Gate
            # -----------------------------------------------------------------
            self._circuit_breakers.check_execution_allowed(
                target=token.channel,
                current_time=now,
            )

            # -----------------------------------------------------------------
            # GATE 5: Capacity Governor Gate
            # -----------------------------------------------------------------
            self._capacity_governor.record_action(
                amount_in_cents=requested_amount_in_cents,
                current_time=now,
            )

            # -----------------------------------------------------------------
            # GATE 6: Sandbox URL Egress Firewall
            # -----------------------------------------------------------------
            self._sandbox_guard.check_egress_allowed(destination_url)

            # -----------------------------------------------------------------
            # GATE 7: Action Dispatch to Sandbox Simulator
            # -----------------------------------------------------------------
            try:
                raw_response = self._sandbox_handler(token.channel, destination_url, payload)
                status = ExecutionStatus.SUCCESS
                error_msg = None
                self._circuit_breakers.record_success(token.channel, current_time=now)
            except Exception as exc:
                self._circuit_breakers.record_failure(token.channel, current_time=now)
                status = ExecutionStatus.FAILED
                error_msg = str(exc)
                raw_response = {"error": str(exc)}

            result = ExecutionResult(
                idempotency_key=token.idempotency_key,
                case_id=token.case_id,
                action_type=token.action_type,
                channel=token.channel,
                amount_in_cents=requested_amount_in_cents,
                destination_url=destination_url,
                status=status,
                response_payload=raw_response,
                error_message=error_msg,
                executed_at=now,
            )

            # -----------------------------------------------------------------
            # GATE 8: Cryptographic Audit Logging & Idempotency Store Commit
            # -----------------------------------------------------------------
            self._idempotency_store.record(result)
            self._audit_logger.append(
                event_type="ACTION_EXECUTED",
                payload={
                    "idempotency_key": result.idempotency_key,
                    "case_id": result.case_id,
                    "action_type": str(result.action_type),
                    "channel": str(result.channel),
                    "amount_in_cents": result.amount_in_cents,
                    "destination_url": result.destination_url,
                    "status": str(result.status),
                    "token_signature": token.signature,
                    "error_message": result.error_message or "",
                },
                timestamp=now,
            )

            if status == ExecutionStatus.FAILED and error_msg:
                raise RuntimeError(f"Sandbox action execution failed: {error_msg}")

            return result
