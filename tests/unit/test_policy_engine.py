"""Comprehensive Unit and Safety Tests for Governance Policy Engine (TICKET-19).

Authoritative Basis:
- Frozen Architecture Baseline v11 Requirements.
- INV-01: AI recommends; it does not execute (Deterministic Policy Engine gates recommendations).
- INV-02: Least-privilege authority boundaries.
- INV-18: Complete audit logging of policy evaluations via append-only cryptographic logger.

Enforces:
1. Policy Lifecycle state machine enforcement (DRAFT through RETIRED).
2. Rule Hierarchy (Tier 1 Legal/Safety -> Tier 2 Business -> Tier 3 Strategy).
3. Conflict Resolution: Strict Deny-Overrides / Fail-Closed.
4. Comprehensive rule domain logic verification.
5. Immutability of policy models and evaluation results.
6. Audit event logging and cryptographic hash chain integrity.
7. Zero execution and zero token-minting capabilities.
8. 100-repetition mathematical determinism.
"""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from src.revenue_recovery.ai_decision.artifacts import DecisionArtifact, create_decision_artifact
from src.revenue_recovery.foundation.audit import CryptographicAuditLogger, ImmutableDict
from src.revenue_recovery.foundation.events import (
    ActionChannel,
    ActionType,
    CaseState,
    RecoveryCase,
    RiskTier,
)
from src.revenue_recovery.governance import (
    DEFAULT_STANDARD_POLICY,
    Policy,
    PolicyEngine,
    PolicyEvaluatedEvent,
    PolicyEvaluationResult,
    PolicyLifecycleState,
    PolicyRule,
    RuleEvaluationResult,
    RuleTier,
    STANDARD_POLICY_RULES,
)
from src.revenue_recovery.recovery_engine.diagnosis import DiagnosisResult


@pytest.fixture
def audit_logger() -> CryptographicAuditLogger:
    return CryptographicAuditLogger()


@pytest.fixture
def standard_case() -> RecoveryCase:
    return RecoveryCase(
        customer_id="cust_gov_001",
        trigger_event_id="evt_gov_001",
        amount_in_cents=25000,
        currency="INR",
        state=CaseState.DIAGNOSED,
        risk_tier=RiskTier.LOW,
        attempt_count=0,
        max_attempts=3,
    )


@pytest.fixture
def standard_diagnosis() -> DiagnosisResult:
    return DiagnosisResult(
        diagnosis_code="TRANSIENT_INSUFFICIENT_FUNDS",
        risk_score=0.2000,
        risk_tier=RiskTier.LOW,
        is_recoverable=True,
        recommended_channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
        rationale="Transient insufficient funds.",
    )


@pytest.fixture
def standard_decision(standard_case: RecoveryCase, standard_diagnosis: DiagnosisResult) -> DecisionArtifact:
    return create_decision_artifact(
        case=standard_case,
        diagnosis=standard_diagnosis,
        model_version="mock-decision-v1.0.0",
    )


# ============================================================================
# PART 1: Policy Lifecycle State Machine Tests
# ============================================================================

class TestPolicyLifecycleStateMachine:
    """Verifies that only authorized policy lifecycle states can permit action execution."""

    @pytest.mark.parametrize(
        "inactive_state",
        [
            PolicyLifecycleState.DRAFT,
            PolicyLifecycleState.REVIEW,
            PolicyLifecycleState.TEST,
            PolicyLifecycleState.SIMULATE,
            PolicyLifecycleState.RETIRED,
        ],
    )
    def test_inactive_policy_lifecycle_states_fail_closed(
        self,
        inactive_state: PolicyLifecycleState,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
    ):
        policy = Policy(
            policy_id=f"policy-{inactive_state.value.lower()}",
            version="1.0.0",
            lifecycle_state=inactive_state,
            rules=STANDARD_POLICY_RULES,
        )
        engine = PolicyEngine(policy_registry={policy.policy_id: policy})
        result = engine.evaluate(
            case=standard_case,
            diagnosis=standard_diagnosis,
            decision=standard_decision,
            policy_id=policy.policy_id,
        )

        assert result.is_allowed is False
        assert any("INACTIVE_POLICY_LIFECYCLE" in v for v in result.violated_rules)

    @pytest.mark.parametrize(
        "active_state",
        [
            PolicyLifecycleState.PRODUCTION,
            PolicyLifecycleState.STAGE,
            PolicyLifecycleState.APPROVED,
        ],
    )
    def test_authorized_policy_lifecycle_states_permit_evaluation(
        self,
        active_state: PolicyLifecycleState,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
    ):
        policy = Policy(
            policy_id=f"policy-{active_state.value.lower()}",
            version="1.0.0",
            lifecycle_state=active_state,
            rules=STANDARD_POLICY_RULES,
        )
        engine = PolicyEngine(policy_registry={policy.policy_id: policy})
        result = engine.evaluate(
            case=standard_case,
            diagnosis=standard_diagnosis,
            decision=standard_decision,
            policy_id=policy.policy_id,
        )

        assert result.is_allowed is True
        assert len(result.violated_rules) == 0

    def test_unregistered_policy_id_fails_closed(
        self,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
    ):
        engine = PolicyEngine()
        result = engine.evaluate(
            case=standard_case,
            diagnosis=standard_diagnosis,
            decision=standard_decision,
            policy_id="non_existent_policy_999",
        )

        assert result.is_allowed is False
        assert any("POLICY_NOT_FOUND" in v for v in result.violated_rules)


# ============================================================================
# PART 2: Rule Hierarchy & Precedence Tests
# ============================================================================

class TestRuleHierarchyAndPrecedence:
    """Verifies that rules are evaluated strictly in Tier 1 -> Tier 2 -> Tier 3 precedence."""

    def test_rule_evaluation_order_respects_tier_precedence(
        self,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
    ):
        # Register rules in scrambled order
        scrambled_rules = (
            STANDARD_POLICY_RULES[7],  # Tier 3
            STANDARD_POLICY_RULES[4],  # Tier 2
            STANDARD_POLICY_RULES[0],  # Tier 1
            STANDARD_POLICY_RULES[6],  # Tier 3
            STANDARD_POLICY_RULES[1],  # Tier 1
            STANDARD_POLICY_RULES[5],  # Tier 2
        )
        policy = Policy(
            policy_id="scrambled-policy",
            version="1.0.0",
            lifecycle_state=PolicyLifecycleState.PRODUCTION,
            rules=scrambled_rules,
        )
        engine = PolicyEngine(policy_registry={policy.policy_id: policy})
        result = engine.evaluate(
            case=standard_case,
            diagnosis=standard_diagnosis,
            decision=standard_decision,
            policy_id=policy.policy_id,
        )

        # Confirm results are sorted strictly by Tier 1 -> Tier 2 -> Tier 3
        tiers = [r.rule_tier for r in result.rule_results]
        tier_ranks = {
            RuleTier.TIER_1_MANDATORY_LEGAL_SAFETY: 1,
            RuleTier.TIER_2_BUSINESS_GOVERNANCE: 2,
            RuleTier.TIER_3_STRATEGY_COMPATIBILITY: 3,
        }
        numeric_ranks = [tier_ranks[t] for t in tiers]
        assert numeric_ranks == sorted(numeric_ranks)


# ============================================================================
# PART 3: Conflict Resolution & Deny-Overrides (Fail-Closed)
# ============================================================================

class TestConflictResolutionAndDenyOverrides:
    """Verifies strict Deny-Overrides: any rule violation yields is_allowed=False."""

    def test_single_tier_1_violation_overrides_all_other_passes(
        self,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
    ):
        # Attempt recovery on a case that has exhausted max attempts
        exhausted_case = RecoveryCase(
            customer_id="cust_ex",
            trigger_event_id="evt_ex",
            amount_in_cents=25000,
            attempt_count=3,
            max_attempts=3,
            state=CaseState.DIAGNOSED,
        )
        decision = create_decision_artifact(case=exhausted_case, diagnosis=standard_diagnosis)
        
        engine = PolicyEngine()
        result = engine.evaluate(exhausted_case, standard_diagnosis, decision)

        assert result.is_allowed is False
        assert any("RULE_T1_MAX_ATTEMPTS_LIMIT" in v for v in result.violated_rules)

    def test_multiple_violations_accumulated_in_tier_order(self):
        # Trigger Tier 1 (Fraud), Tier 2 (Direct Gateway on High Risk), and Tier 3 (Low Confidence)
        case = RecoveryCase(
            customer_id="cust_multi",
            trigger_event_id="evt_multi",
            amount_in_cents=50000,
            risk_tier=RiskTier.BLOCKED,
            attempt_count=0,
            max_attempts=3,
            state=CaseState.DIAGNOSED,
        )
        fraud_diagnosis = DiagnosisResult(
            diagnosis_code="FRAUD_RISK_BLOCK",
            risk_score=1.0000,
            risk_tier=RiskTier.BLOCKED,
            is_recoverable=False,
            recommended_channel=ActionChannel.INTERNAL_SYSTEM,
            rationale="Fraud block",
        )
        # Create an unauthorized decision trying to retry payment with low confidence
        malicious_decision = DecisionArtifact(
            artifact_id="art_malicious",
            case_id=case.case_id,
            model_version="mock-v1",
            prompt_version="v1",
            tool_schema_version="v1",
            canonical_input_hash="0" * 64,
            input_snapshot=ImmutableDict({}),
            recommended_action=ActionType.RETRY_CHARGE,
            parameters=ImmutableDict({"amount_in_cents": 50000, "channel": "DIRECT_PAYMENT_GATEWAY"}),
            confidence_score=0.2000,  # Below 0.5000 threshold
            reasoning_summary="Attempting charge despite fraud",
            created_at=datetime.now(timezone.utc),
        )

        engine = PolicyEngine()
        result = engine.evaluate(case, fraud_diagnosis, malicious_decision)

        assert result.is_allowed is False
        # Multiple violations must be recorded
        assert len(result.violated_rules) >= 3
        assert any("RULE_T1_FRAUD_BLOCK" in v for v in result.violated_rules)
        assert any("RULE_T1_NON_RECOVERABLE_BLOCK" in v for v in result.violated_rules)
        assert any("RULE_T3_MIN_CONFIDENCE_THRESHOLD" in v for v in result.violated_rules)


# ============================================================================
# PART 4: Individual Rule Validation Logic
# ============================================================================

class TestIndividualRuleValidations:
    """Verifies detailed domain logic for all standard rules."""

    def test_rule_t1_fraud_block_allows_no_action(self):
        case = RecoveryCase(
            customer_id="cust_f",
            trigger_event_id="evt_f",
            amount_in_cents=10000,
            risk_tier=RiskTier.BLOCKED,
            state=CaseState.DIAGNOSED,
        )
        diagnosis = DiagnosisResult(
            diagnosis_code="FRAUD_RISK_BLOCK",
            risk_score=1.0000,
            risk_tier=RiskTier.BLOCKED,
            is_recoverable=False,
            recommended_channel=ActionChannel.INTERNAL_SYSTEM,
            rationale="Fraud",
        )
        decision = create_decision_artifact(case, diagnosis)
        assert decision.recommended_action == ActionType.NO_ACTION

        engine = PolicyEngine()
        result = engine.evaluate(case, diagnosis, decision)
        assert result.is_allowed is True

    def test_rule_t1_safety_freeze_guard_blocks_frozen_cases(
        self,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
    ):
        frozen_case = RecoveryCase(
            customer_id="cust_fz",
            trigger_event_id="evt_fz",
            amount_in_cents=20000,
            state=CaseState.FROZEN,
        )
        engine = PolicyEngine()
        result = engine.evaluate(frozen_case, standard_diagnosis, standard_decision)
        assert result.is_allowed is False
        assert any("RULE_T1_SAFETY_FREEZE_GUARD" in v for v in result.violated_rules)

    def test_rule_t2_high_risk_channel_restriction(self, standard_case: RecoveryCase):
        high_risk_diagnosis = DiagnosisResult(
            diagnosis_code="AUTH_STEP_UP_REQUIRED",
            risk_score=0.7500,
            risk_tier=RiskTier.HIGH,
            is_recoverable=True,
            recommended_channel=ActionChannel.EMAIL,
            rationale="Step-up required",
        )
        # Compliant recommendation uses EMAIL
        compliant_decision = create_decision_artifact(standard_case, high_risk_diagnosis)
        engine = PolicyEngine()
        assert engine.evaluate(standard_case, high_risk_diagnosis, compliant_decision).is_allowed is True

        # Non-compliant recommendation tries DIRECT_PAYMENT_GATEWAY on HIGH risk
        bad_decision = DecisionArtifact(
            artifact_id="art_bad",
            case_id=standard_case.case_id,
            model_version="mock-v1",
            prompt_version="v1",
            tool_schema_version="v1",
            canonical_input_hash="0" * 64,
            input_snapshot=ImmutableDict({}),
            recommended_action=ActionType.RETRY_CHARGE,
            parameters=ImmutableDict({"amount_in_cents": 25000, "channel": "DIRECT_PAYMENT_GATEWAY"}),
            confidence_score=0.9000,
            reasoning_summary="Bad retry",
            created_at=datetime.now(timezone.utc),
        )
        res = engine.evaluate(standard_case, high_risk_diagnosis, bad_decision)
        assert res.is_allowed is False
        assert any("RULE_T2_HIGH_RISK_CHANNEL_RESTRICTION" in v for v in res.violated_rules)

    def test_rule_t2_amount_exceeding_case_amount_fails(
        self,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
    ):
        bad_amount_decision = DecisionArtifact(
            artifact_id="art_amt",
            case_id=standard_case.case_id,
            model_version="mock-v1",
            prompt_version="v1",
            tool_schema_version="v1",
            canonical_input_hash="0" * 64,
            input_snapshot=ImmutableDict({}),
            recommended_action=ActionType.RETRY_CHARGE,
            parameters=ImmutableDict({"amount_in_cents": 999999, "channel": "DIRECT_PAYMENT_GATEWAY"}),
            confidence_score=0.9000,
            reasoning_summary="Exceeded amount",
            created_at=datetime.now(timezone.utc),
        )
        engine = PolicyEngine()
        res = engine.evaluate(standard_case, standard_diagnosis, bad_amount_decision)
        assert res.is_allowed is False
        assert any("RULE_T2_ACTION_AMOUNT_BOUND" in v for v in res.violated_rules)


# ============================================================================
# PART 5: Immutability, Audit Trail & Determinism (INV-18)
# ============================================================================

class TestGovernanceImmutabilityAndAudit:
    """Verifies immutability, audit event recording, and reproducibility."""

    def test_policy_and_result_immutability(
        self,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
    ):
        engine = PolicyEngine()
        result = engine.evaluate(standard_case, standard_diagnosis, standard_decision)

        with pytest.raises((ValidationError, TypeError)):
            result.is_allowed = False  # type: ignore

        with pytest.raises((ValidationError, TypeError)):
            DEFAULT_STANDARD_POLICY.lifecycle_state = PolicyLifecycleState.RETIRED  # type: ignore

    def test_audit_logger_records_policy_evaluated_event(
        self,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
        audit_logger: CryptographicAuditLogger,
    ):
        t0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
        engine = PolicyEngine(audit_logger=audit_logger)
        result = engine.evaluate(
            case=standard_case,
            diagnosis=standard_diagnosis,
            decision=standard_decision,
            current_time=t0,
        )

        assert len(audit_logger.entries) == 1
        entry = audit_logger.entries[0]
        assert entry.event_type == "POLICY_EVALUATED"
        assert entry.payload["case_id"] == standard_case.case_id
        assert entry.payload["policy_id"] == DEFAULT_STANDARD_POLICY.policy_id
        assert entry.payload["is_allowed"] is True
        assert entry.timestamp == t0

        # Verify cryptographic audit chain integrity
        assert audit_logger.verify_chain_integrity() is True

    def test_100_repetition_determinism(
        self,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
    ):
        engine = PolicyEngine()
        evals = [
            engine.evaluate(standard_case, standard_diagnosis, standard_decision)
            for _ in range(100)
        ]
        first = evals[0]
        for e in evals:
            assert e.is_allowed == first.is_allowed
            assert e.violated_rules == first.violated_rules
            assert len(e.rule_results) == len(first.rule_results)


# ============================================================================
# PART 6: Authority & Isolation Boundaries (INV-01, INV-02)
# ============================================================================

class TestPolicyEngineAuthorityBoundaries:
    """Verifies that PolicyEngine has zero execution or authorization authority."""

    def test_engine_has_no_execution_or_minting_methods(self):
        engine = PolicyEngine()
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
            assert not hasattr(engine, method_name), f"PolicyEngine must NOT have method '{method_name}'"
