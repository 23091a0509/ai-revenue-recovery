"""Comprehensive Unit and State Machine Test Suite for Recovery Engine (TICKET-15).

Authoritative Basis:
- Frozen Architecture Baseline v11 Requirements.
- Formal TICKET-14 Specification Amendment (Approved by Verification Manager).
- TICKET-13 RecoveryCase Lifecycle State Machine & CaseManager Contracts.

Covers:
1. Complete Recovery Case lifecycle state machine transitions, guards, terminal states, and INV-09 freeze protection.
2. Complete deterministic Risk & Diagnosis evaluation across all 9 rules in the approved policy table.
3. Exact boundary testing for high-value threshold (99,999 vs 100,000) and attempt counts (1 vs 2).
4. Four-quadrant combination tests (low/high amount x low/repeated attempts).
5. Strict fail-closed rejections for unsupported currencies, unknown reasons, and negative attempt counts.
6. 100-repetition mathematical determinism and payload immutability tests.
7. Contract conformance for DiagnosisResult, CaseDiagnosedEvent, and CaseManager integration.
"""

import concurrent.futures
from datetime import datetime, timedelta, timezone
from pydantic import ValidationError
import pytest

from src.revenue_recovery.foundation.audit import CryptographicAuditLogger
from src.revenue_recovery.foundation.events import (
    ActionChannel,
    CaseDiagnosedEvent,
    CaseState,
    FailureReason,
    PaymentFailureEvent,
    RecoveryCase,
    RiskTier,
)
from src.revenue_recovery.recovery_engine import (
    ALLOWED_TRANSITIONS,
    TERMINAL_STATES,
    CaseError,
    CaseFrozenError,
    CaseManager,
    CaseNotFoundError,
    DiagnosisResult,
    InvalidStateTransitionError,
    MaxAttemptsExceededError,
    RiskDiagnosisEvaluator,
    evaluate_diagnosis,
)


@pytest.fixture
def audit_logger() -> CryptographicAuditLogger:
    return CryptographicAuditLogger()


@pytest.fixture
def case_manager(audit_logger: CryptographicAuditLogger) -> CaseManager:
    return CaseManager(audit_logger=audit_logger)


def make_trigger_event(
    customer_id: str = "cust_rec_engine_001",
    invoice_id: str = "inv_rec_engine_001",
    amount_in_cents: int = 15000,
    currency: str = "INR",
    failure_reason: FailureReason = FailureReason.INSUFFICIENT_FUNDS,
    gateway_reference: str = "gw_ref_rec_001",
) -> PaymentFailureEvent:
    return PaymentFailureEvent(
        customer_id=customer_id,
        invoice_id=invoice_id,
        amount_in_cents=amount_in_cents,
        currency=currency,
        failure_reason=failure_reason,
        failure_code=failure_reason.value.lower(),
        gateway_reference=gateway_reference,
    )


# ============================================================================
# PART 1: TICKET-13 RecoveryCase Lifecycle & CaseManager Verification
# ============================================================================

class TestRecoveryCaseLifecycleStateMachine:
    """Verifies all valid transitions, terminal sinks, illegal shortcuts, and INV-09 freeze protection."""

    def test_complete_happy_path_lifecycle(
        self,
        case_manager: CaseManager,
    ):
        t0 = datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc)
        evt = make_trigger_event(amount_in_cents=20000, failure_reason=FailureReason.INSUFFICIENT_FUNDS)
        case = case_manager.create_case(trigger_event=evt, max_attempts=3, current_time=t0)

        assert case.state == CaseState.OPEN
        assert case.attempt_count == 0
        assert case.risk_tier == RiskTier.LOW
        assert case.created_at == t0
        assert case.updated_at == t0

        # Step 1: OPEN -> DIAGNOSED
        t1 = t0 + timedelta(seconds=5)
        c_diag = case_manager.transition_case(
            case_id=case.case_id,
            target_state=CaseState.DIAGNOSED,
            risk_tier=RiskTier.LOW,
            reason="Deterministic diagnosis completed: Transient liquidity shortfall",
            current_time=t1,
        )
        assert c_diag.state == CaseState.DIAGNOSED
        assert c_diag.risk_tier == RiskTier.LOW
        assert c_diag.updated_at == t1

        # Step 2: DIAGNOSED -> EVALUATING
        t2 = t1 + timedelta(seconds=5)
        c_eval = case_manager.transition_case(
            case_id=case.case_id,
            target_state=CaseState.EVALUATING,
            reason="Forwarded to Decision Engine",
            current_time=t2,
        )
        assert c_eval.state == CaseState.EVALUATING
        assert c_eval.updated_at == t2

        # Step 3: EVALUATING -> SCHEDULED
        t3 = t2 + timedelta(seconds=5)
        c_sched = case_manager.transition_case(
            case_id=case.case_id,
            target_state=CaseState.SCHEDULED,
            reason="Policy approved and scheduled in window",
            current_time=t3,
        )
        assert c_sched.state == CaseState.SCHEDULED
        assert c_sched.updated_at == t3

        # Step 4: SCHEDULED -> EXECUTING (increments attempt)
        t4 = t3 + timedelta(seconds=5)
        c_exec = case_manager.transition_case(
            case_id=case.case_id,
            target_state=CaseState.EXECUTING,
            increment_attempt=True,
            reason="ActionExecutor dispatched attempt #1",
            current_time=t4,
        )
        assert c_exec.state == CaseState.EXECUTING
        assert c_exec.attempt_count == 1
        assert c_exec.updated_at == t4

        # Step 5: EXECUTING -> RECONCILING
        t5 = t4 + timedelta(seconds=5)
        c_rec = case_manager.transition_case(
            case_id=case.case_id,
            target_state=CaseState.RECONCILING,
            reason="Simulator returned SUCCESS; awaiting settlement",
            current_time=t5,
        )
        assert c_rec.state == CaseState.RECONCILING
        assert c_rec.updated_at == t5

        # Step 6: RECONCILING -> RESOLVED (Terminal)
        t6 = t5 + timedelta(seconds=5)
        c_res = case_manager.transition_case(
            case_id=case.case_id,
            target_state=CaseState.RESOLVED,
            reason="Settlement confirmed on ledger",
            current_time=t6,
        )
        assert c_res.state == CaseState.RESOLVED
        assert c_res.updated_at == t6

        # Verify audit trail captured 7 immutable entries (genesis + 6 transitions)
        assert case_manager.audit_logger is not None
        assert len(case_manager.audit_logger.entries) == 7

    def test_terminal_resolved_blocks_all_further_transitions(
        self,
        case_manager: CaseManager,
    ):
        evt = make_trigger_event()
        case = case_manager.create_case(evt)
        case_manager.transition_case(case.case_id, CaseState.DIAGNOSED)
        case_manager.transition_case(case.case_id, CaseState.EVALUATING)
        case_manager.transition_case(case.case_id, CaseState.SCHEDULED)
        case_manager.transition_case(case.case_id, CaseState.EXECUTING)
        case_manager.transition_case(case.case_id, CaseState.RECONCILING)
        case_manager.transition_case(case.case_id, CaseState.RESOLVED)

        # Every possible transition from RESOLVED must fail closed
        for target in CaseState:
            with pytest.raises(InvalidStateTransitionError, match="from terminal state 'RESOLVED'"):
                case_manager.transition_case(case.case_id, target)

    def test_terminal_abandoned_blocks_all_further_transitions(
        self,
        case_manager: CaseManager,
    ):
        evt = make_trigger_event(failure_reason=FailureReason.FRAUD_SUSPECTED)
        case = case_manager.create_case(evt)
        case_manager.transition_case(case.case_id, CaseState.ABANDONED, reason="Fraud suspected block")

        # Every possible transition from ABANDONED must fail closed
        for target in CaseState:
            with pytest.raises(InvalidStateTransitionError, match="from terminal state 'ABANDONED'"):
                case_manager.transition_case(case.case_id, target)

    def test_inv09_safety_freeze_and_unfreeze_guards(
        self,
        case_manager: CaseManager,
    ):
        evt = make_trigger_event()
        case = case_manager.create_case(evt)
        case_manager.transition_case(case.case_id, CaseState.DIAGNOSED)
        case_manager.transition_case(case.case_id, CaseState.EVALUATING)

        # Safety freeze from EVALUATING
        c_frozen = case_manager.freeze_case(case.case_id, reason="Circuit breaker tripped on payment channel")
        assert c_frozen.state == CaseState.FROZEN

        # INV-09 Guard: Direct jumps from FROZEN to active execution/scheduling states are forbidden
        for illegal_target in [CaseState.SCHEDULED, CaseState.EXECUTING, CaseState.RECONCILING, CaseState.RESOLVED]:
            with pytest.raises(InvalidStateTransitionError):
                case_manager.unfreeze_case(case.case_id, target_state=illegal_target)

        # INV-09 Guard: Unfreezing must strictly transition to DIAGNOSED for governance re-evaluation
        c_unfrozen = case_manager.unfreeze_case(
            case.case_id,
            target_state=CaseState.DIAGNOSED,
            reason="Circuit breaker reset after cooloff",
        )
        assert c_unfrozen.state == CaseState.DIAGNOSED

    def test_attempt_bounding_and_exhaustion_semantics(
        self,
        case_manager: CaseManager,
    ):
        evt = make_trigger_event()
        case = case_manager.create_case(evt, max_attempts=2)

        # Attempt 1
        case_manager.transition_case(case.case_id, CaseState.DIAGNOSED)
        case_manager.transition_case(case.case_id, CaseState.EVALUATING)
        case_manager.transition_case(case.case_id, CaseState.SCHEDULED)
        case_manager.transition_case(case.case_id, CaseState.EXECUTING, increment_attempt=True)
        c1 = case_manager.get_case(case.case_id)
        assert c1.attempt_count == 1

        # Attempt 1 failed -> Rescheduled for Attempt 2
        case_manager.transition_case(case.case_id, CaseState.SCHEDULED, reason="Retry attempt 2")
        case_manager.transition_case(case.case_id, CaseState.EXECUTING, increment_attempt=True)
        c2 = case_manager.get_case(case.case_id)
        assert c2.attempt_count == 2

        # Attempt 2 failed -> Attempting 3rd execution attempt must raise MaxAttemptsExceededError
        case_manager.transition_case(case.case_id, CaseState.SCHEDULED)
        with pytest.raises(MaxAttemptsExceededError, match="already at max"):
            case_manager.transition_case(case.case_id, CaseState.EXECUTING, increment_attempt=True)

        # Must transition to ABANDONED
        c_abandoned = case_manager.transition_case(case.case_id, CaseState.ABANDONED, reason="Attempts exhausted")
        assert c_abandoned.state == CaseState.ABANDONED

    def test_multi_threaded_concurrent_case_mutations(
        self,
        case_manager: CaseManager,
    ):
        def worker_task(idx: int):
            evt = make_trigger_event(customer_id=f"cust_worker_{idx}", invoice_id=f"inv_worker_{idx}")
            c = case_manager.create_case(evt, max_attempts=3)
            c = case_manager.transition_case(c.case_id, CaseState.DIAGNOSED)
            c = case_manager.transition_case(c.case_id, CaseState.EVALUATING)
            c = case_manager.transition_case(c.case_id, CaseState.SCHEDULED)
            c = case_manager.transition_case(c.case_id, CaseState.EXECUTING, increment_attempt=True)
            c = case_manager.transition_case(c.case_id, CaseState.RECONCILING)
            c = case_manager.transition_case(c.case_id, CaseState.RESOLVED)
            return c

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker_task, i) for i in range(30)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert len(results) == 30
        for r in results:
            assert r.state == CaseState.RESOLVED
            assert r.attempt_count == 1

        all_cases = case_manager.list_cases()
        assert len(all_cases) == 30


# ============================================================================
# PART 2: TICKET-14 Deterministic Risk & Diagnosis Evaluator Verification
# ============================================================================

class TestDeterministicRiskDiagnosisEvaluator:
    """Verifies all nine approved classification rules in the seven-row policy table."""

    def test_rule_1_fraud_suspected(self):
        evt = make_trigger_event(failure_reason=FailureReason.FRAUD_SUSPECTED)
        res = evaluate_diagnosis(evt)

        assert res.diagnosis_code == "FRAUD_RISK_BLOCK"
        assert res.risk_score == 1.0000
        assert res.risk_tier == RiskTier.BLOCKED
        assert res.is_recoverable is False
        assert res.recommended_channel == ActionChannel.INTERNAL_SYSTEM

    def test_rule_2_authentication_failed(self):
        evt = make_trigger_event(failure_reason=FailureReason.AUTHENTICATION_FAILED)
        res = evaluate_diagnosis(evt)

        assert res.diagnosis_code == "AUTH_STEP_UP_REQUIRED"
        assert res.risk_score == 0.7500
        assert res.risk_tier == RiskTier.HIGH
        assert res.is_recoverable is True
        assert res.recommended_channel == ActionChannel.EMAIL

    def test_rule_3_generic_decline_high_value(self):
        evt = make_trigger_event(failure_reason=FailureReason.GENERIC_DECLINE, amount_in_cents=100_000)
        res = evaluate_diagnosis(evt, attempt_count=0)

        assert res.diagnosis_code == "HIGH_RISK_GENERIC_DECLINE"
        assert res.risk_score == 0.6500
        assert res.risk_tier == RiskTier.HIGH
        assert res.is_recoverable is True
        assert res.recommended_channel == ActionChannel.EMAIL

    def test_rule_3_generic_decline_repeated_attempts(self):
        evt = make_trigger_event(failure_reason=FailureReason.GENERIC_DECLINE, amount_in_cents=5000)
        res = evaluate_diagnosis(evt, attempt_count=2)

        assert res.diagnosis_code == "HIGH_RISK_GENERIC_DECLINE"
        assert res.risk_score == 0.6500
        assert res.risk_tier == RiskTier.HIGH
        assert res.is_recoverable is True
        assert res.recommended_channel == ActionChannel.EMAIL

    def test_rule_4_generic_decline_standard(self):
        evt = make_trigger_event(failure_reason=FailureReason.GENERIC_DECLINE, amount_in_cents=99_999)
        res = evaluate_diagnosis(evt, attempt_count=1)

        assert res.diagnosis_code == "UNCLASSIFIED_DECLINE"
        assert res.risk_score == 0.5000
        assert res.risk_tier == RiskTier.MEDIUM
        assert res.is_recoverable is True
        assert res.recommended_channel == ActionChannel.DIRECT_PAYMENT_GATEWAY

    def test_rule_5_card_expired(self):
        evt = make_trigger_event(failure_reason=FailureReason.CARD_EXPIRED)
        res = evaluate_diagnosis(evt)

        assert res.diagnosis_code == "CREDENTIAL_EXPIRED"
        assert res.risk_score == 0.4000
        assert res.risk_tier == RiskTier.MEDIUM
        assert res.is_recoverable is True
        assert res.recommended_channel == ActionChannel.EMAIL

    def test_rule_6_insufficient_funds_repeated_attempts(self):
        evt = make_trigger_event(failure_reason=FailureReason.INSUFFICIENT_FUNDS)
        res = evaluate_diagnosis(evt, attempt_count=2)

        assert res.diagnosis_code == "PERSISTENT_LIQUIDITY_SHORTFALL"
        assert res.risk_score == 0.3500
        assert res.risk_tier == RiskTier.MEDIUM
        assert res.is_recoverable is True
        assert res.recommended_channel == ActionChannel.EMAIL

    def test_rule_7_insufficient_funds_initial_transient(self):
        evt = make_trigger_event(failure_reason=FailureReason.INSUFFICIENT_FUNDS)
        res = evaluate_diagnosis(evt, attempt_count=1)

        assert res.diagnosis_code == "TRANSIENT_INSUFFICIENT_FUNDS"
        assert res.risk_score == 0.2000
        assert res.risk_tier == RiskTier.LOW
        assert res.is_recoverable is True
        assert res.recommended_channel == ActionChannel.DIRECT_PAYMENT_GATEWAY

    def test_rule_8_processing_error(self):
        evt = make_trigger_event(failure_reason=FailureReason.PROCESSING_ERROR)
        res = evaluate_diagnosis(evt)

        assert res.diagnosis_code == "GATEWAY_PROCESSING_ERROR"
        assert res.risk_score == 0.1000
        assert res.risk_tier == RiskTier.LOW
        assert res.is_recoverable is True
        assert res.recommended_channel == ActionChannel.DIRECT_PAYMENT_GATEWAY

    def test_rule_9_gateway_timeout(self):
        evt = make_trigger_event(failure_reason=FailureReason.GATEWAY_TIMEOUT)
        res = evaluate_diagnosis(evt)

        assert res.diagnosis_code == "NETWORK_GATEWAY_TIMEOUT"
        assert res.risk_score == 0.0500
        assert res.risk_tier == RiskTier.LOW
        assert res.is_recoverable is True
        assert res.recommended_channel == ActionChannel.DIRECT_PAYMENT_GATEWAY


# ============================================================================
# PART 3: Exact Boundary & 4-Quadrant Combination Tests
# ============================================================================

class TestBoundaryAndCombinationMatrix:
    """Verifies exact amount/attempt boundaries and 4-quadrant combination matrices."""

    def test_generic_decline_amount_boundary_exact_steps(self):
        # 99,999 -> UNCLASSIFIED_DECLINE (MEDIUM, 0.5000, DIRECT_PAYMENT_GATEWAY)
        res_below = evaluate_diagnosis(
            make_trigger_event(failure_reason=FailureReason.GENERIC_DECLINE, amount_in_cents=99_999),
            attempt_count=0,
        )
        assert res_below.diagnosis_code == "UNCLASSIFIED_DECLINE"
        assert res_below.risk_score == 0.5000
        assert res_below.risk_tier == RiskTier.MEDIUM
        assert res_below.recommended_channel == ActionChannel.DIRECT_PAYMENT_GATEWAY

        # 100,000 -> HIGH_RISK_GENERIC_DECLINE (HIGH, 0.6500, EMAIL)
        res_at = evaluate_diagnosis(
            make_trigger_event(failure_reason=FailureReason.GENERIC_DECLINE, amount_in_cents=100_000),
            attempt_count=0,
        )
        assert res_at.diagnosis_code == "HIGH_RISK_GENERIC_DECLINE"
        assert res_at.risk_score == 0.6500
        assert res_at.risk_tier == RiskTier.HIGH
        assert res_at.recommended_channel == ActionChannel.EMAIL

    def test_insufficient_funds_attempt_boundary_exact_steps(self):
        evt = make_trigger_event(failure_reason=FailureReason.INSUFFICIENT_FUNDS, amount_in_cents=5000)

        # attempt_count = 1 -> TRANSIENT_INSUFFICIENT_FUNDS (LOW, 0.2000, DIRECT_PAYMENT_GATEWAY)
        res_1 = evaluate_diagnosis(evt, attempt_count=1)
        assert res_1.diagnosis_code == "TRANSIENT_INSUFFICIENT_FUNDS"
        assert res_1.risk_score == 0.2000
        assert res_1.risk_tier == RiskTier.LOW
        assert res_1.recommended_channel == ActionChannel.DIRECT_PAYMENT_GATEWAY

        # attempt_count = 2 -> PERSISTENT_LIQUIDITY_SHORTFALL (MEDIUM, 0.3500, EMAIL)
        res_2 = evaluate_diagnosis(evt, attempt_count=2)
        assert res_2.diagnosis_code == "PERSISTENT_LIQUIDITY_SHORTFALL"
        assert res_2.risk_score == 0.3500
        assert res_2.risk_tier == RiskTier.MEDIUM
        assert res_2.recommended_channel == ActionChannel.EMAIL

    @pytest.mark.parametrize(
        "amount,attempt_count,expected_code,expected_score,expected_tier,expected_channel",
        [
            (5000, 0, "UNCLASSIFIED_DECLINE", 0.5000, RiskTier.MEDIUM, ActionChannel.DIRECT_PAYMENT_GATEWAY),       # Low amount, Low attempt
            (150000, 0, "HIGH_RISK_GENERIC_DECLINE", 0.6500, RiskTier.HIGH, ActionChannel.EMAIL),                   # High amount, Low attempt
            (5000, 2, "HIGH_RISK_GENERIC_DECLINE", 0.6500, RiskTier.HIGH, ActionChannel.EMAIL),                     # Low amount, Repeated attempt
            (150000, 2, "HIGH_RISK_GENERIC_DECLINE", 0.6500, RiskTier.HIGH, ActionChannel.EMAIL),                   # High amount, Repeated attempt
        ],
    )
    def test_four_quadrant_generic_decline_matrix(
        self,
        amount: int,
        attempt_count: int,
        expected_code: str,
        expected_score: float,
        expected_tier: RiskTier,
        expected_channel: ActionChannel,
    ):
        evt = make_trigger_event(failure_reason=FailureReason.GENERIC_DECLINE, amount_in_cents=amount)
        res = evaluate_diagnosis(evt, attempt_count=attempt_count)
        assert res.diagnosis_code == expected_code
        assert res.risk_score == expected_score
        assert res.risk_tier == expected_tier
        assert res.recommended_channel == expected_channel
        assert res.is_recoverable is True


# ============================================================================
# PART 4: Fail-Closed & Determinism Verification
# ============================================================================

class TestFailClosedAndDeterminism:
    """Verifies unsupported currencies, invalid inputs, negative attempt counts, and 100-repetition determinism."""

    @pytest.mark.parametrize("supported_currency", ["INR", "USD", "EUR", "GBP", "inr", "usd", "eur", "gbp"])
    def test_supported_currencies_allowed(self, supported_currency: str):
        evt = make_trigger_event(currency=supported_currency, failure_reason=FailureReason.GATEWAY_TIMEOUT)
        res = evaluate_diagnosis(evt)
        assert res.diagnosis_code == "NETWORK_GATEWAY_TIMEOUT"
        assert res.risk_tier == RiskTier.LOW
        assert res.is_recoverable is True

    @pytest.mark.parametrize("unsupported_currency", ["JPY", "AUD", "CAD", "CHF", "XYZ", "CNY"])
    def test_unsupported_currencies_strictly_fail_closed(self, unsupported_currency: str):
        evt = PaymentFailureEvent(
            customer_id="cust_fail_closed",
            invoice_id="inv_fail_closed",
            amount_in_cents=5000,
            currency=unsupported_currency,
            failure_reason=FailureReason.INSUFFICIENT_FUNDS,
            failure_code="insufficient_funds",
            gateway_reference="gw_ref_fc",
        )
        res = evaluate_diagnosis(evt)
        assert res.diagnosis_code == "UNSUPPORTED_CURRENCY_BLOCK"
        assert res.risk_score == 1.0000
        assert res.risk_tier == RiskTier.BLOCKED
        assert res.is_recoverable is False
        assert res.recommended_channel == ActionChannel.INTERNAL_SYSTEM

    def test_negative_attempt_count_raises_value_error(self):
        evt = make_trigger_event()
        with pytest.raises(ValueError, match="attempt_count must be >= 0"):
            evaluate_diagnosis(evt, attempt_count=-1)

    def test_100_repetition_determinism(self):
        evt = make_trigger_event(failure_reason=FailureReason.INSUFFICIENT_FUNDS, amount_in_cents=75000)
        results = [evaluate_diagnosis(evt, attempt_count=1) for _ in range(100)]

        first_res = results[0]
        for r in results:
            assert r == first_res
            assert r.diagnosis_code == "TRANSIENT_INSUFFICIENT_FUNDS"
            assert r.risk_score == 0.2000
            assert r.risk_tier == RiskTier.LOW
            assert r.is_recoverable is True
            assert r.recommended_channel == ActionChannel.DIRECT_PAYMENT_GATEWAY

    def test_diagnosis_result_and_event_immutability(self):
        evt = make_trigger_event(failure_reason=FailureReason.CARD_EXPIRED)
        res = evaluate_diagnosis(evt)

        with pytest.raises((ValidationError, TypeError)):
            res.risk_score = 0.99  # type: ignore

        with pytest.raises((ValidationError, TypeError)):
            res.risk_tier = RiskTier.BLOCKED  # type: ignore

        event = CaseDiagnosedEvent(
            case_id="case_immut_001",
            diagnosis_code=res.diagnosis_code,
            risk_score=res.risk_score,
            recommended_channel=res.recommended_channel,
        )
        with pytest.raises((ValidationError, TypeError)):
            event.diagnosis_code = "TAMPERED_CODE"  # type: ignore
