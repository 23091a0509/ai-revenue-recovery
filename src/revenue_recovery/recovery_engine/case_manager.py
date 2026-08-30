"""Recovery Case lifecycle state machine and authoritative case manager (TICKET-13).

Architecture Baseline: Frozen Architecture Baseline v11.
Enforces:
- Authoritative state machine transitions across all 9 CaseState values.
- Strict transition guards, terminal state locking, and attempt bounding.
- Thread-safe concurrency control for atomic state mutations.
- Monotonic timestamp advancement and cryptographic audit logging.
"""

from datetime import datetime, timezone
import threading
from typing import Dict, List, Optional, Set, Tuple

from src.revenue_recovery.foundation.audit import CryptographicAuditLogger
from src.revenue_recovery.foundation.events import (
    CaseState,
    PaymentFailureEvent,
    RecoveryCase,
    RiskTier,
)


class CaseError(Exception):
    """Base exception for recovery case operations."""
    pass


class CaseNotFoundError(CaseError):
    """Raised when an operation references a non-existent case_id."""
    pass


class InvalidStateTransitionError(CaseError):
    """Raised when an illegal or unsupported state transition is attempted."""
    pass


class MaxAttemptsExceededError(CaseError):
    """Raised when an action attempt is requested on a case that has exhausted max_attempts."""
    pass


class CaseFrozenError(CaseError):
    """Raised when attempting an unauthorized transition on a FROZEN case."""
    pass


# Explicit Allowed Transitions Table (v11 Baseline)
ALLOWED_TRANSITIONS: Dict[CaseState, Set[CaseState]] = {
    CaseState.OPEN: {
        CaseState.DIAGNOSED,
        CaseState.FROZEN,
        CaseState.ABANDONED,
    },
    CaseState.DIAGNOSED: {
        CaseState.EVALUATING,
        CaseState.ABANDONED,
        CaseState.FROZEN,
    },
    CaseState.EVALUATING: {
        CaseState.SCHEDULED,
        CaseState.ABANDONED,
        CaseState.FROZEN,
    },
    CaseState.SCHEDULED: {
        CaseState.EXECUTING,
        CaseState.ABANDONED,
        CaseState.FROZEN,
    },
    CaseState.EXECUTING: {
        CaseState.RECONCILING,
        CaseState.SCHEDULED,
        CaseState.ABANDONED,
        CaseState.FROZEN,
    },
    CaseState.RECONCILING: {
        CaseState.RESOLVED,
        CaseState.SCHEDULED,
        CaseState.ABANDONED,
        CaseState.FROZEN,
    },
    CaseState.FROZEN: {
        CaseState.OPEN,
        CaseState.DIAGNOSED,
        CaseState.EVALUATING,
        CaseState.SCHEDULED,
        CaseState.ABANDONED,
    },
    # Terminal states have no allowed outbound transitions
    CaseState.RESOLVED: set(),
    CaseState.ABANDONED: set(),
}

TERMINAL_STATES: Set[CaseState] = {
    CaseState.RESOLVED,
    CaseState.ABANDONED,
}


class CaseManager:
    """
    Authoritative state machine manager and in-memory registry for Recovery Cases.
    Guarantees thread-safe atomic transitions, monotonic timestamp progression,
    and audit trail emission for every lifecycle event.
    """

    def __init__(self, audit_logger: Optional[CryptographicAuditLogger] = None) -> None:
        self._audit_logger = audit_logger
        self._cases: Dict[str, RecoveryCase] = {}
        self._locks: Dict[str, threading.RLock] = {}
        self._global_lock = threading.RLock()

    @property
    def audit_logger(self) -> Optional[CryptographicAuditLogger]:
        """Returns the attached audit logger instance."""
        return self._audit_logger

    def _get_case_lock(self, case_id: str) -> threading.RLock:
        """Retrieves or creates a thread lock for a specific case."""
        with self._global_lock:
            if case_id not in self._locks:
                self._locks[case_id] = threading.RLock()
            return self._locks[case_id]

    def create_case(
        self,
        trigger_event: PaymentFailureEvent,
        max_attempts: int = 3,
        current_time: Optional[datetime] = None,
    ) -> RecoveryCase:
        """
        Ingests a PaymentFailureEvent and initializes a new RecoveryCase in OPEN state.
        """
        now = current_time or datetime.now(timezone.utc)
        if max_attempts < 1:
            raise ValueError(f"max_attempts must be >= 1, got {max_attempts}")

        case = RecoveryCase(
            customer_id=trigger_event.customer_id,
            trigger_event_id=trigger_event.event_id,
            amount_in_cents=trigger_event.amount_in_cents,
            currency=trigger_event.currency,
            state=CaseState.OPEN,
            risk_tier=RiskTier.LOW,
            attempt_count=0,
            max_attempts=max_attempts,
            created_at=now,
            updated_at=now,
        )

        with self._global_lock:
            self._cases[case.case_id] = case

        if self._audit_logger is not None:
            self._audit_logger.append(
                event_type="CASE_CREATED",
                payload={
                    "case_id": case.case_id,
                    "customer_id": case.customer_id,
                    "trigger_event_id": trigger_event.event_id,
                    "amount_in_cents": case.amount_in_cents,
                    "currency": case.currency,
                    "state": str(case.state.value if hasattr(case.state, 'value') else case.state),
                    "risk_tier": str(case.risk_tier.value if hasattr(case.risk_tier, 'value') else case.risk_tier),
                    "max_attempts": case.max_attempts,
                },
                timestamp=now,
            )

        return case

    def get_case(self, case_id: str) -> Optional[RecoveryCase]:
        """Retrieves a recovery case by ID."""
        with self._global_lock:
            return self._cases.get(case_id)

    def transition_case(
        self,
        case_id: str,
        target_state: CaseState,
        reason: str = "",
        risk_tier: Optional[RiskTier] = None,
        increment_attempt: bool = False,
        current_time: Optional[datetime] = None,
    ) -> RecoveryCase:
        """
        Executes an authoritative state transition with strict guard validation.
        """
        lock = self._get_case_lock(case_id)
        with lock:
            current_case = self.get_case(case_id)
            if current_case is None:
                raise CaseNotFoundError(f"Recovery case with ID '{case_id}' does not exist")

            now = current_time or datetime.now(timezone.utc)

            # Ensure monotonic timestamp progression
            if now < current_case.updated_at:
                now = current_case.updated_at

            current_state_val = current_case.state.value if hasattr(current_case.state, 'value') else str(current_case.state)
            target_state_val = target_state.value if hasattr(target_state, 'value') else str(target_state)

            # Guard 1: Terminal state checks
            if current_case.state in TERMINAL_STATES:
                raise InvalidStateTransitionError(
                    f"Cannot transition case '{case_id}' from terminal state '{current_state_val}' to '{target_state_val}'"
                )

            # Guard 2: State transition graph validation
            allowed = ALLOWED_TRANSITIONS.get(current_case.state, set())
            if target_state not in allowed:
                raise InvalidStateTransitionError(
                    f"Invalid transition for case '{case_id}': '{current_state_val}' -> '{target_state_val}' is not permitted"
                )

            # Guard 3: Attempt limit checks
            new_attempt_count = current_case.attempt_count
            if increment_attempt:
                if current_case.attempt_count >= current_case.max_attempts:
                    raise MaxAttemptsExceededError(
                        f"Case '{case_id}' cannot increment attempt count: already at max ({current_case.max_attempts})"
                    )
                new_attempt_count += 1

            # Guard 4: If scheduling/executing, ensure attempts are not already exhausted
            if target_state in {CaseState.SCHEDULED, CaseState.EXECUTING} and new_attempt_count > current_case.max_attempts:
                raise MaxAttemptsExceededError(
                    f"Case '{case_id}' cannot transition to '{target_state_val}': max attempts ({current_case.max_attempts}) exhausted"
                )

            new_risk_tier = risk_tier if risk_tier is not None else current_case.risk_tier

            # Construct new immutable RecoveryCase
            updated_case = current_case.model_copy(
                update={
                    "state": target_state,
                    "risk_tier": new_risk_tier,
                    "attempt_count": new_attempt_count,
                    "updated_at": now,
                }
            )

            with self._global_lock:
                self._cases[case_id] = updated_case

            if self._audit_logger is not None:
                self._audit_logger.append(
                    event_type="CASE_TRANSITIONED",
                    payload={
                        "case_id": case_id,
                        "from_state": current_state_val,
                        "to_state": target_state_val,
                        "risk_tier": updated_case.risk_tier.value if hasattr(updated_case.risk_tier, 'value') else str(updated_case.risk_tier),
                        "attempt_count": updated_case.attempt_count,
                        "max_attempts": updated_case.max_attempts,
                        "reason": reason,
                    },
                    timestamp=now,
                )

            return updated_case

    def freeze_case(
        self,
        case_id: str,
        reason: str,
        current_time: Optional[datetime] = None,
    ) -> RecoveryCase:
        """
        Freezes an active case due to safety trip, kill switch, or administrative freeze.
        """
        return self.transition_case(
            case_id=case_id,
            target_state=CaseState.FROZEN,
            reason=f"Safety freeze: {reason}",
            current_time=current_time,
        )

    def unfreeze_case(
        self,
        case_id: str,
        target_state: CaseState,
        reason: str,
        current_time: Optional[datetime] = None,
    ) -> RecoveryCase:
        """
        Unfreezes a previously FROZEN case to an operable state after safety clearance.
        """
        current_case = self.get_case(case_id)
        if current_case is None:
            raise CaseNotFoundError(f"Recovery case with ID '{case_id}' does not exist")

        if current_case.state != CaseState.FROZEN:
            state_val = current_case.state.value if hasattr(current_case.state, 'value') else str(current_case.state)
            raise CaseError(f"Case '{case_id}' is not in FROZEN state (current: '{state_val}')")

        return self.transition_case(
            case_id=case_id,
            target_state=target_state,
            reason=f"Safety unfreeze: {reason}",
            current_time=current_time,
        )

    def list_cases(
        self,
        state: Optional[CaseState] = None,
        customer_id: Optional[str] = None,
    ) -> List[RecoveryCase]:
        """Filters stored cases by state and/or customer_id."""
        with self._global_lock:
            results = list(self._cases.values())

        if state is not None:
            results = [c for c in results if c.state == state]
        if customer_id is not None:
            results = [c for c in results if c.customer_id == customer_id]

        return results
