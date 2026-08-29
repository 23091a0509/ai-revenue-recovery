"""Authoritative Action Executor for AI Revenue Recovery MVP.

Architecture Baseline: Frozen Architecture Baseline v11.
Enforces:
- INV-03: Capability-based Action Authorization
- INV-04: Executor acts ONLY on valid signed token (strict independent request-to-token scope binding)
- INV-05: Strict MVP Sandbox Isolation (via integrated SandboxGuard evaluated before capacity reservation)
- INV-16: Idempotency across execution and retry
"""

from datetime import datetime, timezone
import threading
from typing import Any, Callable, Dict, Optional

from src.revenue_recovery.foundation.audit import CryptographicAuditLogger
from src.revenue_recovery.foundation.events import (
    ActionChannel,
    ActionType,
    ExecutionStatus,
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
from src.revenue_recovery.executor.idempotency import (
    ExecutionRequest,
    ExecutionResult,
    IdempotencyConflictError,
    IdempotencyStore,
)
from src.revenue_recovery.executor.sandbox_guard import (
    SandboxGuard,
    SandboxViolationError,
)

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
        request: ExecutionRequest,
        token: ActionAuthorization,
        current_time: Optional[datetime] = None,
    ) -> ExecutionResult:
        """
        Executes an independent recovery action request under strict 8-step safety enforcement:
        1. Cryptographic Authorization Verification & Request Scope Binding:
           - Validates signature and TTL
           - Binds request.customer_id, request.currency, request.amount_in_cents, request.channel
           - Binds request.case_id, request.action_type, request.idempotency_key against token
        2. Idempotency pre-check (replay return or conflict detection)
        3. Kill switch gate (Global, Channel, Action, Customer, Case)
        4. Circuit breaker gate (State check and half-open probe reservation)
        5. Sandbox egress firewall (Scheme, Userinfo, Domain, IP, DNS rebinding)
        6. Capacity governor gate (Count and monetary volume rate limits)
        7. Action dispatch to Sandbox simulator (Updates circuit breaker health)
        8. Audit logging and Idempotency store commit (Returns ExecutionResult)
        """
        now = current_time or datetime.now(timezone.utc)

        # ---------------------------------------------------------------------
        # GATE 1: Cryptographic Authorization Verification & Request Scope Binding
        # ---------------------------------------------------------------------
        # 1a. Validate cryptographic HMAC signature, expiration, customer, currency, amount bound, channel
        self._authorizer.verify_authorization(
            token=token,
            expected_customer_id=request.customer_id,
            expected_currency=request.currency,
            requested_amount_in_cents=request.amount_in_cents,
            expected_channel=request.channel,
            current_time=now,
        )

        # 1b. Validate additional independent request fields against authorized token
        if token.case_id != request.case_id:
            raise AuthorizationVerificationError(
                f"Scope mismatch: Request case_id '{request.case_id}' does not match authorized token case_id '{token.case_id}'"
            )
        if token.action_type != request.action_type:
            raise AuthorizationVerificationError(
                f"Scope mismatch: Request action_type '{request.action_type}' does not match authorized token action_type '{token.action_type}'"
            )
        if token.idempotency_key != request.idempotency_key:
            raise AuthorizationVerificationError(
                f"Scope mismatch: Request idempotency_key '{request.idempotency_key}' does not match authorized token idempotency_key '{token.idempotency_key}'"
            )

        with self._execution_lock:
            # -----------------------------------------------------------------
            # GATE 2: Idempotency Pre-Check
            # -----------------------------------------------------------------
            existing_record = self._idempotency_store.get(request.idempotency_key)
            if existing_record is not None:
                if not existing_record.matches_request(request):
                    raise IdempotencyConflictError(
                        f"Idempotency key '{request.idempotency_key}' was already processed with different parameters. "
                        "Conflicting re-execution rejected."
                    )
                # Idempotent replay: return existing result without re-executing
                return existing_record

            # -----------------------------------------------------------------
            # GATE 3: Kill Switch Gate
            # -----------------------------------------------------------------
            self._kill_switch.check_execution_allowed(
                action_type=request.action_type,
                channel=request.channel,
                customer_id=request.customer_id,
                case_id=request.case_id,
            )

            # -----------------------------------------------------------------
            # GATE 4: Circuit Breaker Gate
            # -----------------------------------------------------------------
            self._circuit_breakers.check_execution_allowed(
                target=request.channel,
                current_time=now,
            )

            # -----------------------------------------------------------------
            # GATE 5: Sandbox URL Egress Firewall (Evaluated BEFORE Capacity Reservation)
            # -----------------------------------------------------------------
            self._sandbox_guard.check_egress_allowed(request.destination_url)

            # -----------------------------------------------------------------
            # GATE 6: Capacity Governor Gate
            # -----------------------------------------------------------------
            self._capacity_governor.record_action(
                amount_in_cents=request.amount_in_cents,
                current_time=now,
            )

            # -----------------------------------------------------------------
            # GATE 7: Action Dispatch to Sandbox Simulator
            # -----------------------------------------------------------------
            try:
                raw_response = self._sandbox_handler(request.channel, request.destination_url, request.action_payload)
                # Check response payload for simulator error status
                if isinstance(raw_response, dict) and raw_response.get("status") in ("FAILED", "ERROR", "DECLINED"):
                    status = ExecutionStatus.FAILED
                    error_msg = raw_response.get("error") or raw_response.get("message") or "Simulator returned failure"
                    self._circuit_breakers.record_failure(request.channel, current_time=now)
                else:
                    status = ExecutionStatus.SUCCESS
                    error_msg = None
                    self._circuit_breakers.record_success(request.channel, current_time=now)
            except Exception as exc:
                self._circuit_breakers.record_failure(request.channel, current_time=now)
                status = ExecutionStatus.FAILED
                error_msg = str(exc)
                raw_response = {"error": str(exc)}

            result = ExecutionResult(
                idempotency_key=request.idempotency_key,
                case_id=request.case_id,
                customer_id=request.customer_id,
                action_type=request.action_type,
                channel=request.channel,
                amount_in_cents=request.amount_in_cents,
                currency=request.currency,
                destination_url=request.destination_url,
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
                    "customer_id": result.customer_id,
                    "action_type": str(result.action_type),
                    "channel": str(result.channel),
                    "amount_in_cents": result.amount_in_cents,
                    "currency": result.currency,
                    "destination_url": result.destination_url,
                    "status": str(result.status),
                    "token_signature": token.signature,
                    "error_message": result.error_message or "",
                },
                timestamp=now,
            )

            return result
