"""Unit tests for deterministic Risk and Diagnosis evaluator (TICKET-14).

Architecture Baseline: Frozen Architecture Baseline v11.
Enforces:
- Pure, deterministic classification of PaymentFailureEvent instances.
- Deterministic risk scoring in [0.0, 1.0] and RiskTier assignment.
- Rule precedence and escalation for attempt counts and high-value amounts.
- Strict fail-closed validation for unknown, invalid, or fraud events.
"""

from datetime import datetime, timezone
import pytest

from src.revenue_recovery.foundation.events import (
    ActionChannel,
    CaseState,
    FailureReason,
    PaymentFailureEvent,
    RiskTier,
)
from src.revenue_recovery.recovery_engine import (
    CaseManager,
    DiagnosisResult,
    RiskDiagnosisEvaluator,
    evaluate_diagnosis,
)


def make_event(
    failure_reason: FailureReason,
    amount_in_cents: int = 5000,
    customer_id: str = "cust_diag_01",
) -> PaymentFailureEvent:
    return PaymentFailureEvent(
        customer_id=customer_id,
        invoice_id="inv_diag_01",
        amount_in_cents=amount_in_cents,
        currency="INR",
        failure_reason=failure_reason,
        failure_code=failure_reason.value.lower(),
        gateway_reference="gw_ref_diag_01",
    )


class TestDeterministicFailureReasonMapping:
    """Verifies all failure reasons map to exact deterministic diagnosis rules."""

    def test_fraud_suspected_blocks_recovery_completely(self):
        evt = make_event(FailureReason.FRAUD_SUSPECTED)
        res = evaluate_diagnosis(evt)

        assert res.diagnosis_code == "FRAUD_RISK_BLOCK"
        assert res.risk_score == 1.0
        assert res.risk_tier == RiskTier.BLOCKED
        assert res.is_recoverable is False
        assert res.recommended_channel == ActionChannel.INTERNAL_SYSTEM

    def test_authentication_failed_requires_step_up(self):
        evt = make_event(FailureReason.AUTHENTICATION_FAILED)
        res = evaluate_diagnosis(evt)

        assert res.diagnosis_code == "AUTH_STEP_UP_REQUIRED"
        assert res.risk_score == 0.75
        assert res.risk_tier == RiskTier.HIGH
        assert res.is_recoverable is True
        assert res.recommended_channel == ActionChannel.EMAIL

    def test_generic_decline_standard(self):
        evt = make_event(FailureReason.GENERIC_DECLINE, amount_in_cents=10000)
        res = evaluate_diagnosis(evt, attempt_count=0)

        assert res.diagnosis_code == "UNCLASSIFIED_DECLINE"
        assert res.risk_score == 0.50
        assert res.risk_tier == RiskTier.MEDIUM
        assert res.is_recoverable is True
        assert res.recommended_channel == ActionChannel.DIRECT_PAYMENT_GATEWAY

    def test_generic_decline_high_value_escalation(self):
        evt = make_event(FailureReason.GENERIC_DECLINE, amount_in_cents=150000)  # > 100,000 cents
        res = evaluate_diagnosis(evt, attempt_count=0)

        assert res.diagnosis_code == "HIGH_RISK_GENERIC_DECLINE"
        assert res.risk_score == 0.65
        assert res.risk_tier == RiskTier.HIGH
        assert res.is_recoverable is True
        assert res.recommended_channel == ActionChannel.EMAIL

    def test_generic_decline_repeated_attempt_escalation(self):
        evt = make_event(FailureReason.GENERIC_DECLINE, amount_in_cents=5000)
        res = evaluate_diagnosis(evt, attempt_count=2)

        assert res.diagnosis_code == "HIGH_RISK_GENERIC_DECLINE"
        assert res.risk_score == 0.65
        assert res.risk_tier == RiskTier.HIGH
        assert res.is_recoverable is True
        assert res.recommended_channel == ActionChannel.EMAIL

    def test_card_expired_requires_customer_update(self):
        evt = make_event(FailureReason.CARD_EXPIRED)
        res = evaluate_diagnosis(evt)

        assert res.diagnosis_code == "CREDENTIAL_EXPIRED"
        assert res.risk_score == 0.40
        assert res.risk_tier == RiskTier.MEDIUM
        assert res.is_recoverable is True
        assert res.recommended_channel == ActionChannel.EMAIL

    def test_insufficient_funds_initial_transient(self):
        evt = make_event(FailureReason.INSUFFICIENT_FUNDS)
        res = evaluate_diagnosis(evt, attempt_count=0)

        assert res.diagnosis_code == "TRANSIENT_INSUFFICIENT_FUNDS"
        assert res.risk_score == 0.20
        assert res.risk_tier == RiskTier.LOW
        assert res.is_recoverable is True
        assert res.recommended_channel == ActionChannel.DIRECT_PAYMENT_GATEWAY

    def test_insufficient_funds_repeated_attempt_escalation(self):
        evt = make_event(FailureReason.INSUFFICIENT_FUNDS)
        res = evaluate_diagnosis(evt, attempt_count=2)

        assert res.diagnosis_code == "PERSISTENT_LIQUIDITY_SHORTFALL"
        assert res.risk_score == 0.35
        assert res.risk_tier == RiskTier.MEDIUM
        assert res.is_recoverable is True
        assert res.recommended_channel == ActionChannel.EMAIL

    def test_processing_error_transient(self):
        evt = make_event(FailureReason.PROCESSING_ERROR)
        res = evaluate_diagnosis(evt)

        assert res.diagnosis_code == "GATEWAY_PROCESSING_ERROR"
        assert res.risk_score == 0.10
        assert res.risk_tier == RiskTier.LOW
        assert res.is_recoverable is True
        assert res.recommended_channel == ActionChannel.DIRECT_PAYMENT_GATEWAY

    def test_gateway_timeout_transient(self):
        evt = make_event(FailureReason.GATEWAY_TIMEOUT)
        res = evaluate_diagnosis(evt)

        assert res.diagnosis_code == "NETWORK_GATEWAY_TIMEOUT"
        assert res.risk_score == 0.05
        assert res.risk_tier == RiskTier.LOW
        assert res.is_recoverable is True
        assert res.recommended_channel == ActionChannel.DIRECT_PAYMENT_GATEWAY


class TestEvaluatorDeterminismAndPurity:
    """Verifies purity and determinism over multiple repetitions."""

    def test_evaluation_is_pure_and_deterministic(self):
        evt = make_event(FailureReason.INSUFFICIENT_FUNDS, amount_in_cents=25000)
        results = [evaluate_diagnosis(evt, attempt_count=1) for _ in range(50)]

        first_res = results[0]
        for r in results:
            assert r == first_res
            assert r.diagnosis_code == "TRANSIENT_INSUFFICIENT_FUNDS"
            assert r.risk_score == 0.20
            assert r.risk_tier == RiskTier.LOW

    def test_negative_attempt_count_rejected(self):
        evt = make_event(FailureReason.INSUFFICIENT_FUNDS)
        with pytest.raises(ValueError, match="attempt_count must be >= 0"):
            evaluate_diagnosis(evt, attempt_count=-1)


class TestCaseManagerDiagnosisIntegration:
    """Verifies integration between RiskDiagnosisEvaluator and CaseManager."""

    def test_case_manager_applies_diagnosis_risk_tier(self):
        cm = CaseManager()
        evt = make_event(FailureReason.AUTHENTICATION_FAILED, amount_in_cents=8000)
        case = cm.create_case(evt)

        assert case.state == CaseState.OPEN
        assert case.risk_tier == RiskTier.LOW

        diag = evaluate_diagnosis(evt)
        assert diag.risk_tier == RiskTier.HIGH

        c_diagnosed = cm.transition_case(
            case_id=case.case_id,
            target_state=CaseState.DIAGNOSED,
            risk_tier=diag.risk_tier,
            reason=diag.rationale,
        )

        assert c_diagnosed.state == CaseState.DIAGNOSED
        assert c_diagnosed.risk_tier == RiskTier.HIGH
