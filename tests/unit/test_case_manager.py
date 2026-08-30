"""Unit tests for CaseManager and RecoveryCase lifecycle state machine (TICKET-13).

Architecture Baseline: Frozen Architecture Baseline v11.
Enforces:
- Authoritative state machine transitions across all 9 CaseState values.
- Strict transition guards, terminal state locking, and attempt bounding.
- Thread-safe concurrency control for atomic state mutations.
- Monotonic timestamp advancement and cryptographic audit logging.
- INV-09: Safety freezes cannot be bypassed via arbitrary state jumping.
"""

import concurrent.futures
from datetime import datetime, timedelta, timezone
import pytest

from src.revenue_recovery.foundation.audit import CryptographicAuditLogger
from src.revenue_recovery.foundation.events import (
    CaseState,
    FailureReason,
    PaymentFailureEvent,
    RecoveryCase,
    RiskTier,
)
from src.revenue_recovery.recovery_engine import (
    CaseError,
    CaseManager,
    CaseNotFoundError,
    InvalidStateTransitionError,
    MaxAttemptsExceededError,
)


@pytest.fixture
def audit_logger() -> CryptographicAuditLogger:
    return CryptographicAuditLogger()


@pytest.fixture
def case_manager(audit_logger: CryptographicAuditLogger) -> CaseManager:
    return CaseManager(audit_logger=audit_logger)


@pytest.fixture
def sample_trigger_event() -> PaymentFailureEvent:
    return PaymentFailureEvent(
        customer_id="cust_lifecycle_001",
        invoice_id="inv_lifecycle_001",
        amount_in_cents=12000,
        currency="INR",
        failure_reason=FailureReason.INSUFFICIENT_FUNDS,
        failure_code="insufficient_funds",
        gateway_reference="gw_ref_001",
    )


class TestCaseManagerGenesisAndLifecycle:
    """Verifies case creation, happy-path progression, and monotonic timestamps."""

    def test_create_case_initializes_open_state(
        self,
        case_manager: CaseManager,
        sample_trigger_event: PaymentFailureEvent,
    ):
        t0 = datetime(2026, 6, 1, 10, 0, 0, tzinfo=timezone.utc)
        case = case_manager.create_case(
            trigger_event=sample_trigger_event,
            max_attempts=3,
            current_time=t0,
        )

        assert case.state == CaseState.OPEN
        assert case.risk_tier == RiskTier.LOW
        assert case.attempt_count == 0
        assert case.max_attempts == 3
        assert case.customer_id == sample_trigger_event.customer_id
        assert case.trigger_event_id == sample_trigger_event.event_id
        assert case.amount_in_cents == 12000
        assert case.currency == "INR"
        assert case.created_at == t0
        assert case.updated_at == t0

        retrieved = case_manager.get_case(case.case_id)
        assert retrieved == case

        assert case_manager.audit_logger is not None
        assert len(case_manager.audit_logger.entries) == 1
        assert case_manager.audit_logger.entries[0].event_type == "CASE_CREATED"
        assert case_manager.audit_logger.entries[0].payload["case_id"] == case.case_id

    def test_full_recovery_happy_path_pipeline(
        self,
        case_manager: CaseManager,
        sample_trigger_event: PaymentFailureEvent,
    ):
        t0 = datetime(2026, 6, 1, 10, 0, 0, tzinfo=timezone.utc)
        case = case_manager.create_case(sample_trigger_event, max_attempts=3, current_time=t0)

        # 1. OPEN -> DIAGNOSED
        t1 = t0 + timedelta(seconds=10)
        c1 = case_manager.transition_case(
            case_id=case.case_id,
            target_state=CaseState.DIAGNOSED,
            risk_tier=RiskTier.MEDIUM,
            reason="Diagnosis evaluated soft failure",
            current_time=t1,
        )
        assert c1.state == CaseState.DIAGNOSED
        assert c1.risk_tier == RiskTier.MEDIUM
        assert c1.updated_at == t1

        # 2. DIAGNOSED -> EVALUATING
        t2 = t1 + timedelta(seconds=10)
        c2 = case_manager.transition_case(
            case_id=case.case_id,
            target_state=CaseState.EVALUATING,
            reason="Forwarded to AI Decision Engine",
            current_time=t2,
        )
        assert c2.state == CaseState.EVALUATING
        assert c2.updated_at == t2

        # 3. EVALUATING -> SCHEDULED
        t3 = t2 + timedelta(seconds=10)
        c3 = case_manager.transition_case(
            case_id=case.case_id,
            target_state=CaseState.SCHEDULED,
            reason="Policy accepted and slot scheduled",
            current_time=t3,
        )
        assert c3.state == CaseState.SCHEDULED
        assert c3.updated_at == t3

        # 4. SCHEDULED -> EXECUTING
        t4 = t3 + timedelta(seconds=10)
        c4 = case_manager.transition_case(
            case_id=case.case_id,
            target_state=CaseState.EXECUTING,
            increment_attempt=True,
            reason="ActionExecutor dispatched attempt #1",
            current_time=t4,
        )
        assert c4.state == CaseState.EXECUTING
        assert c4.attempt_count == 1
        assert c4.updated_at == t4

        # 5. EXECUTING -> RECONCILING
        t5 = t4 + timedelta(seconds=10)
        c5 = case_manager.transition_case(
            case_id=case.case_id,
            target_state=CaseState.RECONCILING,
            reason="Charge succeeded; awaiting ledger reconciliation",
            current_time=t5,
        )
        assert c5.state == CaseState.RECONCILING
        assert c5.updated_at == t5

        # 6. RECONCILING -> RESOLVED (Terminal)
        t6 = t5 + timedelta(seconds=10)
        c6 = case_manager.transition_case(
            case_id=case.case_id,
            target_state=CaseState.RESOLVED,
            reason="Settlement confirmed on ledger",
            current_time=t6,
        )
        assert c6.state == CaseState.RESOLVED
        assert c6.updated_at == t6

        # Audit logger captured all transitions
        assert case_manager.audit_logger is not None
        assert len(case_manager.audit_logger.entries) == 7  # 1 created + 6 transitions


class TestTerminalAndInvalidStateTransitions:
    """Verifies that terminal states and invalid transitions fail closed."""

    def test_resolved_terminal_state_blocks_all_further_transitions(
        self,
        case_manager: CaseManager,
        sample_trigger_event: PaymentFailureEvent,
    ):
        case = case_manager.create_case(sample_trigger_event)
        case_manager.transition_case(case.case_id, CaseState.DIAGNOSED)
        case_manager.transition_case(case.case_id, CaseState.EVALUATING)
        case_manager.transition_case(case.case_id, CaseState.SCHEDULED)
        case_manager.transition_case(case.case_id, CaseState.EXECUTING)
        case_manager.transition_case(case.case_id, CaseState.RECONCILING)
        case_manager.transition_case(case.case_id, CaseState.RESOLVED)

        # Attempting any transition from RESOLVED must fail closed
        for target in [CaseState.OPEN, CaseState.SCHEDULED, CaseState.EXECUTING, CaseState.ABANDONED, CaseState.FROZEN]:
            with pytest.raises(InvalidStateTransitionError, match="Cannot transition case .* from terminal state 'RESOLVED'"):
                case_manager.transition_case(case.case_id, target)

    def test_abandoned_terminal_state_blocks_all_further_transitions(
        self,
        case_manager: CaseManager,
        sample_trigger_event: PaymentFailureEvent,
    ):
        case = case_manager.create_case(sample_trigger_event)
        case_manager.transition_case(case.case_id, CaseState.ABANDONED, reason="Non-recoverable fraud")

        for target in [CaseState.OPEN, CaseState.DIAGNOSED, CaseState.SCHEDULED, CaseState.RESOLVED, CaseState.FROZEN]:
            with pytest.raises(InvalidStateTransitionError, match="Cannot transition case .* from terminal state 'ABANDONED'"):
                case_manager.transition_case(case.case_id, target)

    @pytest.mark.parametrize(
        "from_state,invalid_targets",
        [
            (CaseState.OPEN, [CaseState.EXECUTING, CaseState.RECONCILING, CaseState.RESOLVED]),
            (CaseState.DIAGNOSED, [CaseState.EXECUTING, CaseState.RECONCILING, CaseState.RESOLVED]),
            (CaseState.EVALUATING, [CaseState.EXECUTING, CaseState.RECONCILING, CaseState.RESOLVED]),
            (CaseState.SCHEDULED, [CaseState.RECONCILING, CaseState.RESOLVED, CaseState.OPEN]),
        ],
    )
    def test_illegal_shortcuts_rejected(
        self,
        case_manager: CaseManager,
        sample_trigger_event: PaymentFailureEvent,
        from_state: CaseState,
        invalid_targets: list,
    ):
        case = case_manager.create_case(sample_trigger_event)
        # Advance case to from_state
        if from_state == CaseState.DIAGNOSED:
            case_manager.transition_case(case.case_id, CaseState.DIAGNOSED)
        elif from_state == CaseState.EVALUATING:
            case_manager.transition_case(case.case_id, CaseState.DIAGNOSED)
            case_manager.transition_case(case.case_id, CaseState.EVALUATING)
        elif from_state == CaseState.SCHEDULED:
            case_manager.transition_case(case.case_id, CaseState.DIAGNOSED)
            case_manager.transition_case(case.case_id, CaseState.EVALUATING)
            case_manager.transition_case(case.case_id, CaseState.SCHEDULED)

        for target in invalid_targets:
            with pytest.raises(InvalidStateTransitionError, match="is not permitted"):
                case_manager.transition_case(case.case_id, target)

    def test_non_existent_case_raises_not_found(self, case_manager: CaseManager):
        with pytest.raises(CaseNotFoundError, match="Recovery case with ID 'case_404' does not exist"):
            case_manager.transition_case("case_404", CaseState.DIAGNOSED)


class TestRetryAndAttemptBounding:
    """Verifies attempt count bounding and exhaustion semantics."""

    def test_retry_loop_until_max_attempts_exhausted(
        self,
        case_manager: CaseManager,
        sample_trigger_event: PaymentFailureEvent,
    ):
        case = case_manager.create_case(sample_trigger_event, max_attempts=2)

        # Attempt 1
        case_manager.transition_case(case.case_id, CaseState.DIAGNOSED)
        case_manager.transition_case(case.case_id, CaseState.EVALUATING)
        case_manager.transition_case(case.case_id, CaseState.SCHEDULED)
        case_manager.transition_case(case.case_id, CaseState.EXECUTING, increment_attempt=True)
        c1 = case_manager.get_case(case.case_id)
        assert c1.attempt_count == 1

        # Execution failure -> Reschedule for Attempt 2
        case_manager.transition_case(case.case_id, CaseState.SCHEDULED, reason="Retry scheduled after decline")
        case_manager.transition_case(case.case_id, CaseState.EXECUTING, increment_attempt=True)
        c2 = case_manager.get_case(case.case_id)
        assert c2.attempt_count == 2

        # Execution failure again -> Attempting 3rd execution attempt must raise MaxAttemptsExceededError
        case_manager.transition_case(case.case_id, CaseState.SCHEDULED)
        with pytest.raises(MaxAttemptsExceededError, match="already at max"):
            case_manager.transition_case(case.case_id, CaseState.EXECUTING, increment_attempt=True)

        # Abandoning case when attempts exhausted
        c_abandoned = case_manager.transition_case(case.case_id, CaseState.ABANDONED, reason="Max attempts exhausted")
        assert c_abandoned.state == CaseState.ABANDONED


class TestSafetyFreezeAndUnfreeze:
    """Verifies freeze and unfreeze capabilities for INV-09 and Kill Switch interactions."""

    def test_freeze_and_unfreeze_lifecycle(
        self,
        case_manager: CaseManager,
        sample_trigger_event: PaymentFailureEvent,
    ):
        case = case_manager.create_case(sample_trigger_event)
        case_manager.transition_case(case.case_id, CaseState.DIAGNOSED)

        # Freeze from DIAGNOSED
        c_frozen = case_manager.freeze_case(case.case_id, reason="Kill switch activated on customer channel")
        assert c_frozen.state == CaseState.FROZEN

        # Frozen case cannot directly execute
        with pytest.raises(InvalidStateTransitionError, match="is not permitted"):
            case_manager.transition_case(case.case_id, CaseState.EXECUTING)

        # Direct unfreeze jump to SCHEDULED/EXECUTING is forbidden per INV-09
        with pytest.raises(InvalidStateTransitionError, match="INV-09 Guard: Cannot unfreeze case .* directly"):
            case_manager.unfreeze_case(case.case_id, target_state=CaseState.SCHEDULED)

        # Unfreeze must strictly re-enter through DIAGNOSED
        c_unfrozen = case_manager.unfreeze_case(
            case.case_id,
            target_state=CaseState.DIAGNOSED,
            reason="Kill switch deactivated",
        )
        assert c_unfrozen.state == CaseState.DIAGNOSED

        # Case can now proceed cleanly to EVALUATING
        c_eval = case_manager.transition_case(case.case_id, CaseState.EVALUATING)
        assert c_eval.state == CaseState.EVALUATING

    def test_unfreeze_non_frozen_case_fails(
        self,
        case_manager: CaseManager,
        sample_trigger_event: PaymentFailureEvent,
    ):
        case = case_manager.create_case(sample_trigger_event)
        with pytest.raises(CaseError, match="is not in FROZEN state"):
            case_manager.unfreeze_case(case.case_id, CaseState.DIAGNOSED, reason="Invalid unfreeze")


class TestCaseManagerConcurrencyAndQueries:
    """Verifies thread-safe concurrency and query capabilities."""

    def test_concurrent_case_creation_and_transitions(
        self,
        case_manager: CaseManager,
        sample_trigger_event: PaymentFailureEvent,
    ):
        def lifecycle_worker(i: int):
            evt = sample_trigger_event.model_copy(update={"customer_id": f"cust_concurrent_{i}"})
            c = case_manager.create_case(evt, max_attempts=3)
            c = case_manager.transition_case(c.case_id, CaseState.DIAGNOSED)
            c = case_manager.transition_case(c.case_id, CaseState.EVALUATING)
            c = case_manager.transition_case(c.case_id, CaseState.SCHEDULED)
            c = case_manager.transition_case(c.case_id, CaseState.EXECUTING, increment_attempt=True)
            c = case_manager.transition_case(c.case_id, CaseState.RECONCILING)
            c = case_manager.transition_case(c.case_id, CaseState.RESOLVED)
            return c

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(lifecycle_worker, i) for i in range(25)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert len(results) == 25
        for r in results:
            assert r.state == CaseState.RESOLVED
            assert r.attempt_count == 1

        all_cases = case_manager.list_cases()
        assert len(all_cases) == 25

        resolved_cases = case_manager.list_cases(state=CaseState.RESOLVED)
        assert len(resolved_cases) == 25
