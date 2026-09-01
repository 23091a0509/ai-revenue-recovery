"""Comprehensive Unit and Security Tests for AI Decision Engine (TICKET-18).

Authoritative Basis:
- Frozen Architecture Baseline v11 Requirements.
- INV-01: AI recommends; it does not execute.
- INV-02: Least-privilege authority boundaries.
- INV-17: Immutable Decision Artifacts with SHA-256 canonical input snapshot hashing.
- INV-18: Complete audit logging of financial and decision transitions.

Enforces:
1. Recommendation-only boundary: Zero execution capability and zero token minting authority.
2. Complete DecisionArtifact validation, parameter contracts, and deep immutability.
3. State precondition enforcement (Case must be DIAGNOSED or EVALUATING).
4. Canonical input snapshot hashing and corrupted/forged hash rejection.
5. Mathematical determinism across repeated executions.
6. Fail-closed safety routing for BLOCKED and non-recoverable risk tiers.
7. Cryptographic audit trail emission and hash chain verification.
"""

from datetime import datetime, timezone
import hashlib
from typing import Optional
from pydantic import ValidationError
import pytest

from src.revenue_recovery.ai_decision import (
    AIDecisionEngine,
    AIModelProvider,
    DecisionArtifact,
    DecisionArtifactCreatedEvent,
    DeterministicAIProvider,
    compute_canonical_input_hash,
    create_decision_artifact,
)
from src.revenue_recovery.executor import (
    ActionExecutor,
    ExecutionRequest,
    create_sandbox_action_handler,
)
from src.revenue_recovery.foundation.audit import (
    CryptographicAuditLogger,
    ImmutableDict,
    canonical_json,
)
from src.revenue_recovery.foundation.events import (
    ActionChannel,
    ActionType,
    CaseState,
    FailureReason,
    RecoveryCase,
    RiskTier,
)
from src.revenue_recovery.recovery_engine.diagnosis import DiagnosisResult
from src.revenue_recovery.safety import (
    CapacityGovernor,
    CircuitBreaker,
    CryptographicAuthorizer,
    KillSwitchManager,
)


@pytest.fixture
def audit_logger() -> CryptographicAuditLogger:
    return CryptographicAuditLogger()


@pytest.fixture
def diagnosed_case() -> RecoveryCase:
    return RecoveryCase(
        customer_id="cust_ai_001",
        trigger_event_id="evt_ai_001",
        amount_in_cents=25000,
        currency="INR",
        state=CaseState.DIAGNOSED,
        risk_tier=RiskTier.LOW,
        attempt_count=0,
        max_attempts=3,
    )


@pytest.fixture
def transient_diagnosis() -> DiagnosisResult:
    return DiagnosisResult(
        diagnosis_code="TRANSIENT_INSUFFICIENT_FUNDS",
        risk_score=0.2000,
        risk_tier=RiskTier.LOW,
        is_recoverable=True,
        recommended_channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
        rationale="Transient liquidity shortfall; eligible for automated retry.",
    )


@pytest.fixture
def high_risk_diagnosis() -> DiagnosisResult:
    return DiagnosisResult(
        diagnosis_code="AUTH_STEP_UP_REQUIRED",
        risk_score=0.7500,
        risk_tier=RiskTier.HIGH,
        is_recoverable=True,
        recommended_channel=ActionChannel.EMAIL,
        rationale="Authentication failed; step-up interactive required.",
    )


@pytest.fixture
def blocked_diagnosis() -> DiagnosisResult:
    return DiagnosisResult(
        diagnosis_code="FRAUD_RISK_BLOCK",
        risk_score=1.0000,
        risk_tier=RiskTier.BLOCKED,
        is_recoverable=False,
        recommended_channel=ActionChannel.INTERNAL_SYSTEM,
        rationale="Suspected fraud detected; automated recovery blocked.",
    )


# ============================================================================
# PART 1: Recommendation-Only & Authority Boundary Tests (INV-01, INV-02)
# ============================================================================

class TestAIRecommendationOnlyAuthorityBoundaries:
    """Verifies that AIDecisionEngine is strictly recommendation-only with zero execution authority."""

    def test_engine_has_no_execution_methods(self):
        engine = AIDecisionEngine()
        forbidden_methods = [
            "execute",
            "execute_action",
            "dispatch",
            "send",
            "call_simulator",
            "charge",
            "retry_payment",
            "mint_token",
            "mint_authorization",
            "authorize",
            "sign",
        ]
        for method_name in forbidden_methods:
            assert not hasattr(engine, method_name), f"AIDecisionEngine must NOT have method '{method_name}'"

    def test_decision_artifact_cannot_be_used_directly_for_execution(
        self,
        diagnosed_case: RecoveryCase,
        transient_diagnosis: DiagnosisResult,
    ):
        engine = AIDecisionEngine()
        artifact = engine.evaluate_case(diagnosed_case, transient_diagnosis)

        # DecisionArtifact contains recommendation parameters, but lacks execution capability
        assert not hasattr(artifact, "execute")
        assert not hasattr(artifact, "dispatch")
        assert not isinstance(artifact, ExecutionRequest)

        # ActionExecutor requires an explicit ExecutionRequest and signed ActionAuthorization token
        assert not hasattr(artifact, "signature")
        assert not hasattr(artifact, "token")

    def test_ai_engine_cannot_mint_authorization_tokens(
        self,
        diagnosed_case: RecoveryCase,
        transient_diagnosis: DiagnosisResult,
    ):
        engine = AIDecisionEngine()
        artifact = engine.evaluate_case(diagnosed_case, transient_diagnosis)

        # Artifact contains no cryptographic signature, token, or secret key
        assert not hasattr(artifact, "signature")
        assert not hasattr(artifact, "token")
        assert not hasattr(artifact, "signing_secret")
        assert not hasattr(artifact, "authorizer")

    def test_custom_provider_conformance_to_protocol(
        self,
        diagnosed_case: RecoveryCase,
        transient_diagnosis: DiagnosisResult,
    ):
        class CustomMockProvider:
            def generate_recommendation(
                self,
                case: RecoveryCase,
                diagnosis: DiagnosisResult,
                current_time: Optional[datetime] = None,
            ) -> DecisionArtifact:
                return create_decision_artifact(
                    case=case,
                    diagnosis=diagnosis,
                    model_version="custom-v2.0",
                )

        provider = CustomMockProvider()
        assert isinstance(provider, AIModelProvider)

        engine = AIDecisionEngine(provider=provider)
        artifact = engine.evaluate_case(diagnosed_case, transient_diagnosis)
        assert artifact.model_version == "custom-v2.0"


# ============================================================================
# PART 2: State Precondition Guards & Fail-Closed Safety
# ============================================================================

class TestStatePreconditionsAndFailClosedSafety:
    """Verifies state requirements, invalid case rejection, and safety routing."""

    @pytest.mark.parametrize(
        "invalid_state",
        [
            CaseState.OPEN,
            CaseState.SCHEDULED,
            CaseState.EXECUTING,
            CaseState.RECONCILING,
            CaseState.RESOLVED,
            CaseState.ABANDONED,
            CaseState.FROZEN,
        ],
    )
    def test_undocumented_or_non_diagnosed_case_states_rejected(
        self,
        invalid_state: CaseState,
        transient_diagnosis: DiagnosisResult,
    ):
        case = RecoveryCase(
            customer_id="cust_state_test",
            trigger_event_id="evt_state_test",
            amount_in_cents=10000,
            state=invalid_state,
        )
        engine = AIDecisionEngine()
        with pytest.raises(ValueError, match="Case must be in DIAGNOSED or EVALUATING state"):
            engine.evaluate_case(case, transient_diagnosis)

    def test_evaluating_state_is_permitted(
        self,
        transient_diagnosis: DiagnosisResult,
    ):
        case = RecoveryCase(
            customer_id="cust_eval_test",
            trigger_event_id="evt_eval_test",
            amount_in_cents=10000,
            state=CaseState.EVALUATING,
        )
        engine = AIDecisionEngine()
        artifact = engine.evaluate_case(case, transient_diagnosis)
        assert artifact.recommended_action == ActionType.RETRY_CHARGE

    def test_blocked_case_fails_closed_to_no_action(
        self,
        blocked_diagnosis: DiagnosisResult,
    ):
        case = RecoveryCase(
            customer_id="cust_blocked",
            trigger_event_id="evt_blocked",
            amount_in_cents=80000,
            state=CaseState.DIAGNOSED,
            risk_tier=RiskTier.BLOCKED,
        )
        engine = AIDecisionEngine()
        artifact = engine.evaluate_case(case, blocked_diagnosis)

        assert artifact.recommended_action == ActionType.NO_ACTION
        assert artifact.confidence_score == 1.0000
        assert artifact.parameters["channel"] == ActionChannel.INTERNAL_SYSTEM.value
        assert artifact.parameters["amount_in_cents"] == 0

    def test_non_recoverable_diagnosis_fails_closed_to_no_action(
        self,
        diagnosed_case: RecoveryCase,
    ):
        unrecov_diagnosis = DiagnosisResult(
            diagnosis_code="UNSUPPORTED_CURRENCY_BLOCK",
            risk_score=1.0000,
            risk_tier=RiskTier.BLOCKED,
            is_recoverable=False,
            recommended_channel=ActionChannel.INTERNAL_SYSTEM,
            rationale="Unsupported currency block",
        )
        engine = AIDecisionEngine()
        artifact = engine.evaluate_case(diagnosed_case, unrecov_diagnosis)

        assert artifact.recommended_action == ActionType.NO_ACTION
        assert artifact.confidence_score == 1.0000


# ============================================================================
# PART 3: Hash Integrity & Tamper Rejection (INV-17)
# ============================================================================

class TestCanonicalInputHashIntegrity:
    """Verifies input snapshot canonical hashing, determinism, and corrupted hash rejection."""

    def test_forged_or_corrupted_hash_rejected_by_engine(
        self,
        diagnosed_case: RecoveryCase,
        transient_diagnosis: DiagnosisResult,
    ):
        class MaliciousProvider:
            def generate_recommendation(
                self,
                case: RecoveryCase,
                diagnosis: DiagnosisResult,
                current_time: Optional[datetime] = None,
            ) -> DecisionArtifact:
                art = create_decision_artifact(case, diagnosis)
                # Construct artifact with forged hash
                return DecisionArtifact(
                    artifact_id=art.artifact_id,
                    case_id=art.case_id,
                    model_version=art.model_version,
                    prompt_version=art.prompt_version,
                    tool_schema_version=art.tool_schema_version,
                    canonical_input_hash="0" * 64,  # Forged hash!
                    input_snapshot=art.input_snapshot,
                    recommended_action=art.recommended_action,
                    parameters=art.parameters,
                    confidence_score=art.confidence_score,
                    reasoning_summary=art.reasoning_summary,
                    created_at=art.created_at,
                )

        engine = AIDecisionEngine(provider=MaliciousProvider())
        with pytest.raises(ValueError, match="Corrupted DecisionArtifact input hash"):
            engine.evaluate_case(diagnosed_case, transient_diagnosis)

    def test_hash_is_invariant_to_key_insertion_order(self):
        d1 = {"a": 1, "b": 2, "c": {"x": 10, "y": 20}}
        d2 = {"c": {"y": 20, "x": 10}, "b": 2, "a": 1}

        assert compute_canonical_input_hash(d1) == compute_canonical_input_hash(d2)

    def test_100_repetition_determinism(
        self,
        diagnosed_case: RecoveryCase,
        transient_diagnosis: DiagnosisResult,
    ):
        engine = AIDecisionEngine()
        results = [engine.evaluate_case(diagnosed_case, transient_diagnosis) for _ in range(100)]

        first = results[0]
        for r in results:
            assert r.canonical_input_hash == first.canonical_input_hash
            assert r.recommended_action == first.recommended_action
            assert r.confidence_score == first.confidence_score
            assert r.parameters == first.parameters


# ============================================================================
# PART 4: Payload Immutability & Audit Integration (INV-18)
# ============================================================================

class TestPayloadImmutabilityAndAuditTrail:
    """Verifies artifact field/payload immutability and append-only audit stream logging."""

    def test_deep_immutability_of_decision_artifact(
        self,
        diagnosed_case: RecoveryCase,
        transient_diagnosis: DiagnosisResult,
    ):
        engine = AIDecisionEngine()
        artifact = engine.evaluate_case(diagnosed_case, transient_diagnosis)

        # Attribute mutation rejected
        with pytest.raises((ValidationError, TypeError)):
            artifact.confidence_score = 0.99  # type: ignore

        with pytest.raises((ValidationError, TypeError)):
            artifact.recommended_action = ActionType.NO_ACTION  # type: ignore

        # ImmutableDict dictionary mutation rejected
        with pytest.raises(TypeError, match="does not support item assignment"):
            artifact.input_snapshot["amount_in_cents"] = 999999

        with pytest.raises(TypeError, match="does not support item assignment"):
            artifact.parameters["channel"] = "FORGED_CHANNEL"

    def test_audit_logger_records_decision_artifact_created_event(
        self,
        diagnosed_case: RecoveryCase,
        transient_diagnosis: DiagnosisResult,
        audit_logger: CryptographicAuditLogger,
    ):
        t0 = datetime(2026, 8, 31, 10, 0, 0, tzinfo=timezone.utc)
        engine = AIDecisionEngine(audit_logger=audit_logger)
        artifact = engine.evaluate_case(diagnosed_case, transient_diagnosis, current_time=t0)

        assert len(audit_logger.entries) == 1
        entry = audit_logger.entries[0]
        assert entry.event_type == "DECISION_ARTIFACT_CREATED"
        assert entry.payload["artifact_id"] == artifact.artifact_id
        assert entry.payload["case_id"] == diagnosed_case.case_id
        assert entry.payload["canonical_input_hash"] == artifact.canonical_input_hash
        assert entry.payload["recommended_action"] == ActionType.RETRY_CHARGE.value
        assert entry.timestamp == t0

        # Verify audit hash chain integrity
        assert audit_logger.verify_chain_integrity() is True
