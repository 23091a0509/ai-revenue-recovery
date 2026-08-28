"""Unit tests for core domain models, enums, and event contracts (TICKET-02).

Architecture Baseline: Frozen Architecture Baseline v11.
"""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from src.revenue_recovery.foundation.events import (
    ActionChannel,
    ActionType,
    CaseState,
    ComplianceObligation,
    DomainEventEnvelope,
    ExecutionStatus,
    FailureReason,
    ObligationType,
    PaymentFailureEvent,
    RecoveryCase,
    RiskTier,
)


class TestFoundationPublicExports:
    """Tests verifying public exports from src.revenue_recovery.foundation."""

    def test_obligation_type_exported_from_foundation(self):
        """Proves that ObligationType is correctly exported and importable from the foundation root."""
        from src.revenue_recovery.foundation import ObligationType as FoundationObligationType
        assert FoundationObligationType is ObligationType
        assert FoundationObligationType.COOLING_OFF.value == "COOLING_OFF"

    def test_all_declared_exports_importable(self):
        """Proves that every symbol declared in foundation.__all__ actually exists and is exported."""
        import src.revenue_recovery.foundation as foundation
        for symbol in foundation.__all__:
            assert hasattr(foundation, symbol), f"Symbol '{symbol}' declared in __all__ but not exported"


class TestCoreDomainEnums:
    """Tests verifying required lifecycle states, action types, and failure reasons."""

    def test_case_state_enum_has_all_v11_states(self):
        expected_states = {
            "OPEN", "DIAGNOSED", "EVALUATING", "SCHEDULED",
            "EXECUTING", "RECONCILING", "RESOLVED", "ABANDONED", "FROZEN"
        }
        actual_states = {state.value for state in CaseState}
        assert actual_states == expected_states

    def test_risk_tier_enum_values(self):
        assert {tier.value for tier in RiskTier} == {"LOW", "MEDIUM", "HIGH", "BLOCKED"}

    def test_failure_reason_enum_values(self):
        expected_reasons = {
            "INSUFFICIENT_FUNDS", "CARD_EXPIRED", "GATEWAY_TIMEOUT",
            "PROCESSING_ERROR", "AUTHENTICATION_FAILED", "FRAUD_SUSPECTED", "GENERIC_DECLINE"
        }
        assert {reason.value for reason in FailureReason} == expected_reasons

    def test_action_type_enum_values(self):
        expected_actions = {
            "RETRY_CHARGE", "SEND_NOTIFICATION", "UPDATE_PAYMENT_METHOD_REQUEST",
            "OFFER_PAYMENT_PLAN", "APPLY_GRACE_PERIOD", "NO_ACTION"
        }
        assert {action.value for action in ActionType} == expected_actions

    def test_action_channel_enum_values(self):
        expected_channels = {
            "DIRECT_PAYMENT_GATEWAY", "EMAIL", "SMS", "WHATSAPP", "INTERNAL_SYSTEM"
        }
        assert {channel.value for channel in ActionChannel} == expected_channels

    def test_obligation_type_enum_values(self):
        expected_obligations = {
            "MANDATORY_DISCLOSURE", "COOLING_OFF", "RETRY_WINDOW", "CONSENT_CHECK"
        }
        assert {ob.value for ob in ObligationType} == expected_obligations

    def test_execution_status_enum_values(self):
        expected_statuses = {"PENDING", "SUCCESS", "FAILED", "BLOCKED", "SKIPPED"}
        assert {status.value for status in ExecutionStatus} == expected_statuses


class TestPaymentFailureEvent:
    """Tests for PaymentFailureEvent construction and validation."""

    def test_valid_payment_failure_event(self):
        event = PaymentFailureEvent(
            customer_id="cust_123",
            invoice_id="inv_999",
            amount_in_cents=5000,
            currency="INR",
            failure_reason=FailureReason.INSUFFICIENT_FUNDS,
            failure_code="insufficient_funds",
            gateway_reference="gw_txn_abc123"
        )
        assert event.customer_id == "cust_123"
        assert event.amount_in_cents == 5000
        assert event.currency == "INR"
        assert event.failure_reason == FailureReason.INSUFFICIENT_FUNDS
        assert event.event_id is not None

    def test_invalid_negative_or_zero_amount_rejected(self):
        with pytest.raises(ValidationError):
            PaymentFailureEvent(
                customer_id="cust_123",
                invoice_id="inv_999",
                amount_in_cents=0,
                currency="INR",
                failure_reason=FailureReason.GENERIC_DECLINE,
                gateway_reference="gw_123"
            )

        with pytest.raises(ValidationError):
            PaymentFailureEvent(
                customer_id="cust_123",
                invoice_id="inv_999",
                amount_in_cents=-100,
                currency="INR",
                failure_reason=FailureReason.GENERIC_DECLINE,
                gateway_reference="gw_123"
            )

    def test_currency_normalized_to_uppercase(self):
        event = PaymentFailureEvent(
            customer_id="cust_123",
            invoice_id="inv_999",
            amount_in_cents=2500,
            currency="usd",
            failure_reason=FailureReason.CARD_EXPIRED,
            gateway_reference="gw_123"
        )
        assert event.currency == "USD"

    def test_invalid_currency_code_rejected(self):
        with pytest.raises(ValidationError):
            PaymentFailureEvent(
                customer_id="cust_123",
                invoice_id="inv_999",
                amount_in_cents=2500,
                currency="INVALID_CODE",
                failure_reason=FailureReason.CARD_EXPIRED,
                gateway_reference="gw_123"
            )

    def test_immutability_prevents_mutation(self):
        event = PaymentFailureEvent(
            customer_id="cust_123",
            invoice_id="inv_999",
            amount_in_cents=5000,
            currency="INR",
            failure_reason=FailureReason.GATEWAY_TIMEOUT,
            gateway_reference="gw_123"
        )
        with pytest.raises(ValidationError):
            event.amount_in_cents = 10000  # type: ignore

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            PaymentFailureEvent(
                customer_id="cust_123",
                invoice_id="inv_999",
                amount_in_cents=5000,
                currency="INR",
                failure_reason=FailureReason.PROCESSING_ERROR,
                gateway_reference="gw_123",
                unauthorized_extra_field="malicious_payload"  # type: ignore
            )


class TestRecoveryCase:
    """Tests for RecoveryCase model integrity."""

    def test_valid_recovery_case_defaults(self):
        case = RecoveryCase(
            customer_id="cust_456",
            trigger_event_id="evt_001",
            amount_in_cents=15000,
            currency="INR"
        )
        assert case.state == CaseState.OPEN
        assert case.risk_tier == RiskTier.LOW
        assert case.attempt_count == 0
        assert case.max_attempts == 3
        assert case.case_id is not None

    def test_immutability_enforced(self):
        case = RecoveryCase(
            customer_id="cust_456",
            trigger_event_id="evt_001",
            amount_in_cents=15000,
            currency="INR"
        )
        with pytest.raises(ValidationError):
            case.state = CaseState.RESOLVED  # type: ignore


class TestComplianceObligation:
    """Tests for ComplianceObligation model."""

    def test_valid_compliance_obligation(self):
        scheduled = datetime.now(timezone.utc)
        obligation = ComplianceObligation(
            case_id="case_789",
            obligation_type=ObligationType.COOLING_OFF,
            scheduled_time=scheduled
        )
        assert obligation.case_id == "case_789"
        assert obligation.obligation_type == ObligationType.COOLING_OFF
        assert obligation.is_mandatory is True
        assert obligation.status == "PENDING"


class TestDomainEventEnvelope:
    """Tests for generic DomainEventEnvelope."""

    def test_valid_envelope_wrapping(self):
        payload = {"sample_key": "sample_value", "amount": 100}
        envelope = DomainEventEnvelope[dict](
            event_type="PaymentFailureTriggered",
            idempotency_key="idemp_key_123",
            correlation_id="corr_abc",
            causation_id="caus_xyz",
            payload=payload
        )
        assert envelope.event_type == "PaymentFailureTriggered"
        assert envelope.idempotency_key == "idemp_key_123"
        assert envelope.payload == payload
        assert envelope.version == "1.0.0"

    def test_envelope_immutability(self):
        envelope = DomainEventEnvelope[dict](
            event_type="CaseCreated",
            idempotency_key="idemp_1",
            correlation_id="corr_1",
            causation_id="caus_1",
            payload={"case_id": "case_1"}
        )
        with pytest.raises(ValidationError):
            envelope.event_type = "CaseMutated"  # type: ignore
