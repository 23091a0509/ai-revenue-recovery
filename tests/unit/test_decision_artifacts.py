"""Unit tests for immutable DecisionArtifact model and canonical input hashing (TICKET-16).

Authoritative Basis:
- Frozen Architecture Baseline v11 Requirements.
- INV-01: AI recommends; it does not execute.
- INV-17: Immutable Decision Artifacts with SHA-256 canonical input snapshot hashing.
"""

from datetime import datetime, timezone
import hashlib
from pydantic import ValidationError
import pytest

from src.revenue_recovery.ai_decision import (
    DecisionArtifact,
    DecisionArtifactCreatedEvent,
    compute_canonical_input_hash,
    create_decision_artifact,
)
from src.revenue_recovery.foundation.audit import ImmutableDict, canonical_json
from src.revenue_recovery.foundation.events import (
    ActionChannel,
    ActionType,
    CaseState,
    FailureReason,
    PaymentFailureEvent,
    RecoveryCase,
    RiskTier,
)
from src.revenue_recovery.recovery_engine.diagnosis import (
    DiagnosisResult,
    evaluate_diagnosis,
)


@pytest.fixture
def sample_case() -> RecoveryCase:
    return RecoveryCase(
        customer_id="cust_art_001",
        trigger_event_id="evt_art_001",
        amount_in_cents=12000,
        currency="INR",
        state=CaseState.DIAGNOSED,
        risk_tier=RiskTier.LOW,
        attempt_count=0,
        max_attempts=3,
    )


@pytest.fixture
def sample_diagnosis() -> DiagnosisResult:
    return DiagnosisResult(
        diagnosis_code="TRANSIENT_INSUFFICIENT_FUNDS",
        risk_score=0.2000,
        risk_tier=RiskTier.LOW,
        is_recoverable=True,
        recommended_channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
        rationale="Transient liquidity shortfall; eligible for automated retry.",
    )


class TestCanonicalInputHashing:
    """Verifies SHA-256 canonical input hashing determinism and tamper sensitivity (INV-17)."""

    def test_canonical_hash_is_key_order_invariant(self):
        dict1 = {"b": 2, "a": 1, "nested": {"y": 20, "x": 10}}
        dict2 = {"a": 1, "b": 2, "nested": {"x": 10, "y": 20}}

        hash1 = compute_canonical_input_hash(dict1)
        hash2 = compute_canonical_input_hash(dict2)

        assert hash1 == hash2
        assert len(hash1) == 64
        # Manual verification
        expected = hashlib.sha256(canonical_json(dict1).encode("utf-8")).hexdigest()
        assert hash1 == expected

    def test_canonical_hash_changes_on_payload_tamper(self):
        base_dict = {"case_id": "c1", "amount": 1000}
        tampered_dict = {"case_id": "c1", "amount": 1001}

        hash_base = compute_canonical_input_hash(base_dict)
        hash_tampered = compute_canonical_input_hash(tampered_dict)

        assert hash_base != hash_tampered


class TestDecisionArtifactValidationAndImmutability:
    """Verifies schema validation, hash formatting, and deep payload immutability."""

    def test_valid_decision_artifact_instantiation(self, sample_case, sample_diagnosis):
        artifact = create_decision_artifact(
            case=sample_case,
            diagnosis=sample_diagnosis,
            model_version="mock-decision-v1.0.0",
        )

        assert artifact.case_id == sample_case.case_id
        assert artifact.model_version == "mock-decision-v1.0.0"
        assert artifact.prompt_version == "v1.0.0"
        assert artifact.tool_schema_version == "v1.0.0"
        assert len(artifact.canonical_input_hash) == 64
        assert artifact.recommended_action == ActionType.RETRY_CHARGE
        assert artifact.confidence_score == 0.8000
        assert isinstance(artifact.input_snapshot, ImmutableDict)
        assert isinstance(artifact.parameters, ImmutableDict)
        assert artifact.parameters["channel"] == ActionChannel.DIRECT_PAYMENT_GATEWAY.value

    def test_invalid_hash_format_rejected(self):
        with pytest.raises(ValidationError, match="canonical_input_hash"):
            DecisionArtifact(
                case_id="case_1",
                model_version="v1",
                prompt_version="v1",
                tool_schema_version="v1",
                canonical_input_hash="invalid_short_hash",
                input_snapshot={"k": "v"},
                recommended_action=ActionType.RETRY_CHARGE,
                parameters={},
                confidence_score=0.9,
                reasoning_summary="summary",
            )

    def test_invalid_confidence_score_rejected(self):
        valid_hash = "a" * 64
        with pytest.raises(ValidationError, match="confidence_score"):
            DecisionArtifact(
                case_id="case_1",
                model_version="v1",
                prompt_version="v1",
                tool_schema_version="v1",
                canonical_input_hash=valid_hash,
                input_snapshot={"k": "v"},
                recommended_action=ActionType.RETRY_CHARGE,
                parameters={},
                confidence_score=1.5,  # > 1.0
                reasoning_summary="summary",
            )

    def test_artifact_and_nested_payload_immutability(self, sample_case, sample_diagnosis):
        artifact = create_decision_artifact(sample_case, sample_diagnosis)

        # Direct attribute assignment must fail
        with pytest.raises((ValidationError, TypeError)):
            artifact.confidence_score = 0.5  # type: ignore

        with pytest.raises((ValidationError, TypeError)):
            artifact.recommended_action = ActionType.NO_ACTION  # type: ignore

        # Mutating input_snapshot dictionary must fail
        with pytest.raises(TypeError, match="does not support item assignment"):
            artifact.input_snapshot["amount_in_cents"] = 999999

        # Mutating parameters dictionary must fail
        with pytest.raises(TypeError, match="does not support item assignment"):
            artifact.parameters["channel"] = "FORGED_CHANNEL"


class TestDecisionEngineRecommendationRouting:
    """Verifies recommendation-only action mapping based on DiagnosisResult (INV-01)."""

    def test_payment_retry_routing_for_direct_gateway(self, sample_case, sample_diagnosis):
        artifact = create_decision_artifact(sample_case, sample_diagnosis)
        assert artifact.recommended_action == ActionType.RETRY_CHARGE
        assert artifact.parameters["channel"] == ActionChannel.DIRECT_PAYMENT_GATEWAY.value
        assert artifact.parameters["amount_in_cents"] == 12000

    def test_notification_routing_for_email_channel(self, sample_case):
        diagnosis_email = DiagnosisResult(
            diagnosis_code="CREDENTIAL_EXPIRED",
            risk_score=0.4000,
            risk_tier=RiskTier.MEDIUM,
            is_recoverable=True,
            recommended_channel=ActionChannel.EMAIL,
            rationale="Card expired; customer notification required.",
        )
        artifact = create_decision_artifact(sample_case, diagnosis_email)
        assert artifact.recommended_action == ActionType.SEND_NOTIFICATION
        assert artifact.parameters["channel"] == ActionChannel.EMAIL.value
        assert artifact.confidence_score == 0.6000

    def test_blocked_risk_tier_routes_to_no_action(self):
        blocked_case = RecoveryCase(
            customer_id="cust_blocked",
            trigger_event_id="evt_blocked",
            amount_in_cents=50000,
            currency="INR",
            state=CaseState.DIAGNOSED,
            risk_tier=RiskTier.BLOCKED,
        )
        diagnosis_blocked = DiagnosisResult(
            diagnosis_code="FRAUD_RISK_BLOCK",
            risk_score=1.0000,
            risk_tier=RiskTier.BLOCKED,
            is_recoverable=False,
            recommended_channel=ActionChannel.INTERNAL_SYSTEM,
            rationale="Fraud detected.",
        )
        artifact = create_decision_artifact(blocked_case, diagnosis_blocked)
        assert artifact.recommended_action == ActionType.NO_ACTION
        assert artifact.parameters["channel"] == ActionChannel.INTERNAL_SYSTEM.value
        assert artifact.parameters["amount_in_cents"] == 0
        assert artifact.confidence_score == 1.0000

    def test_evaluating_un_diagnosed_case_raises_value_error(self, sample_diagnosis):
        open_case = RecoveryCase(
            customer_id="cust_open",
            trigger_event_id="evt_open",
            amount_in_cents=1000,
            state=CaseState.OPEN,
        )
        with pytest.raises(ValueError, match="Expected DIAGNOSED or EVALUATING"):
            create_decision_artifact(open_case, sample_diagnosis)


class TestDecisionArtifactCreatedEvent:
    """Verifies domain event contract for DecisionArtifact creation."""

    def test_event_instantiation_and_immutability(self, sample_case, sample_diagnosis):
        artifact = create_decision_artifact(sample_case, sample_diagnosis)
        event = DecisionArtifactCreatedEvent(
            artifact_id=artifact.artifact_id,
            case_id=artifact.case_id,
            canonical_input_hash=artifact.canonical_input_hash,
            model_version=artifact.model_version,
            recommended_action=artifact.recommended_action,
        )

        assert event.artifact_id == artifact.artifact_id
        assert event.case_id == sample_case.case_id
        assert event.canonical_input_hash == artifact.canonical_input_hash
        assert event.model_version == artifact.model_version
        assert event.recommended_action == ActionType.RETRY_CHARGE

        with pytest.raises((ValidationError, TypeError)):
            event.recommended_action = ActionType.NO_ACTION  # type: ignore
