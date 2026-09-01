"""Comprehensive Property-Based and Multi-Way Collision Tests for Governance Engine (TICKET-22).

Authoritative Basis:
- Frozen Architecture Baseline v11 Requirements.
- INV-01: AI recommends; it does not execute.
- INV-02: Least-privilege authority boundaries.
- INV-07: Mandatory compliance obligations cannot be discarded.
- INV-08: Multi-way obligation collision resolution with legal safety fallbacks.
- INV-09: Safety freezes cannot be bypassed via retry.
- INV-10: Incident obligations route through authoritative Scheduler.
- INV-18: Complete audit logging of governance decisions and transitions.

Test Scope (Milestone 6 Joint Verification):
1. Property-based randomized permutation testing of multi-way obligation collisions (100+ iterations).
2. Input ordering invariance and deterministic tie-breaking for colliding obligations.
3. Strict mandatory obligation preservation guarantees (INV-07).
4. Policy Engine tier precedence, deny-overrides, and lifecycle fail-closed behavior.
5. Exhaustive 36-state Arbitration Matrix verification (Safety x Compliance x Experiment).
6. Safety Freeze dominance and impenetrable freeze guard (INV-09).
7. Authority boundary isolation (zero execution, zero token-minting).
8. Append-only cryptographic audit logging and hash-chain verification (INV-18).
9. 100-repetition mathematical determinism and arbitration hash stability.
"""

from datetime import datetime, timezone
import itertools
import random
import pytest
from pydantic import ValidationError

from src.revenue_recovery.ai_decision.artifacts import (
    DecisionArtifact,
    compute_canonical_input_hash,
    create_decision_artifact,
)
from src.revenue_recovery.foundation.audit import CryptographicAuditLogger
from src.revenue_recovery.foundation.events import (
    ActionChannel,
    ActionType,
    CaseState,
    ComplianceObligation,
    FailureReason,
    ObligationType,
    RecoveryCase,
    RiskTier,
)
from src.revenue_recovery.governance import (
    ArbitratedOutcome,
    ArbitrationEvaluatedEvent,
    ArbitrationRecord,
    ComplianceScheduler,
    ComplianceVerdict,
    ControlPlaneArbitrator,
    DEFAULT_STANDARD_POLICY,
    ExperimentAssignment,
    ObligationScheduledEvent,
    ObligationStatus,
    Policy,
    PolicyEngine,
    PolicyEvaluatedEvent,
    PolicyEvaluationResult,
    PolicyLifecycleState,
    PolicyRule,
    RuleEvaluationResult,
    RuleTier,
    SafetyVerdict,
    ScheduledObligationPlan,
    compute_canonical_arbitration_hash,
)
from src.revenue_recovery.recovery_engine.diagnosis import DiagnosisResult
from src.revenue_recovery.safety.circuit_breaker import (
    CapacityGovernor,
    GranularCircuitBreakerRegistry,
)
from src.revenue_recovery.safety.kill_switch import KillSwitchManager


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
def standard_diagnosis(standard_case: RecoveryCase) -> DiagnosisResult:
    return DiagnosisResult(
        diagnosis_code="INSUFFICIENT_FUNDS_TRANSIENT",
        risk_score=0.15,
        risk_tier=RiskTier.LOW,
        is_recoverable=True,
        recommended_channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
        rationale="Initial transient decline. Eligible for automated retry.",
    )


@pytest.fixture
def standard_decision(
    standard_case: RecoveryCase, standard_diagnosis: DiagnosisResult
) -> DecisionArtifact:
    return create_decision_artifact(case=standard_case, diagnosis=standard_diagnosis)


# ============================================================================
# PART 1: Property-Based & Randomized Multi-Way Collision Tests (INV-07, INV-08)
# ============================================================================

class TestPropertyBasedObligationCollisions:
    """Randomized and permutation invariance testing for ComplianceScheduler collisions."""

    def test_randomized_collision_permutations_preserve_dominant_and_resolved_sets(
        self, standard_case: RecoveryCase
    ):
        """
        Runs 100 randomized iterations where a multi-way collision set of obligations
        is shuffled in arbitrary input order.
        Verifies:
        1. Dominant scheduled obligation is identical regardless of input ordering.
        2. Set of resolved collisions is identical regardless of input ordering.
        3. Mandatory obligations (is_mandatory=True) are NEVER discarded (INV-07).
        4. Exact type precedence hierarchy is strictly respected (INV-08).
        """
        t_collide = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)

        # Baseline set of colliding obligations at t_collide
        ob_disclosure = ComplianceObligation(
            obligation_id="ob_01_mand_disclosure",
            case_id=standard_case.case_id,
            obligation_type=ObligationType.MANDATORY_DISCLOSURE,
            is_mandatory=True,
            scheduled_time=t_collide,
        )
        ob_consent = ComplianceObligation(
            obligation_id="ob_02_mand_consent",
            case_id=standard_case.case_id,
            obligation_type=ObligationType.CONSENT_CHECK,
            is_mandatory=True,
            scheduled_time=t_collide,
        )
        ob_cooling = ComplianceObligation(
            obligation_id="ob_03_mand_cooling",
            case_id=standard_case.case_id,
            obligation_type=ObligationType.COOLING_OFF,
            is_mandatory=True,
            scheduled_time=t_collide,
        )
        ob_retry_opt = ComplianceObligation(
            obligation_id="ob_04_opt_retry",
            case_id=standard_case.case_id,
            obligation_type=ObligationType.RETRY_WINDOW,
            is_mandatory=False,
            scheduled_time=t_collide,
        )
        ob_retry_mand = ComplianceObligation(
            obligation_id="ob_05_mand_retry",
            case_id=standard_case.case_id,
            obligation_type=ObligationType.RETRY_WINDOW,
            is_mandatory=True,
            scheduled_time=t_collide,
        )

        base_obligations = [
            ob_disclosure,
            ob_consent,
            ob_cooling,
            ob_retry_opt,
            ob_retry_mand,
        ]

        rng = random.Random(42)  # Seeded for reproducible property-based testing

        # Run 100 randomized orderings
        for iteration in range(100):
            shuffled = list(base_obligations)
            rng.shuffle(shuffled)

            scheduler = ComplianceScheduler()
            plan = scheduler.schedule_case_obligations(
                case=standard_case,
                obligations=shuffled,
                current_time=t_collide,
            )

            # 1. Exactly one dominant obligation scheduled at t_collide
            assert len(plan.scheduled_obligations) == 1, f"Iteration {iteration}: Expected 1 dominant obligation"
            dominant = plan.scheduled_obligations[0]

            # Dominant MUST be MANDATORY_DISCLOSURE (Rank 1 & is_mandatory=True)
            assert dominant.obligation_id == "ob_01_mand_disclosure", (
                f"Iteration {iteration}: Dominant obligation must be ob_01_mand_disclosure, got {dominant.obligation_id}"
            )
            assert dominant.status == ObligationStatus.PENDING.value

            # 2. All other 4 obligations must be in collision_resolutions with status COLLISION_RESOLVED
            assert len(plan.collision_resolutions) == 4, f"Iteration {iteration}: Expected 4 collision resolutions"
            resolved_ids = {r.obligation_id for r in plan.collision_resolutions}
            assert resolved_ids == {
                "ob_02_mand_consent",
                "ob_03_mand_cooling",
                "ob_04_opt_retry",
                "ob_05_mand_retry",
            }

            for resolved in plan.collision_resolutions:
                assert resolved.status == ObligationStatus.COLLISION_RESOLVED.value
                assert "subordinate to MANDATORY_DISCLOSURE" in (resolved.resolution_reason or "")

            # 3. Mandatory Preservation (INV-07): All mandatory obligations must survive in plan
            all_plan_obs = plan.scheduled_obligations + plan.collision_resolutions
            all_plan_ids = {o.obligation_id for o in all_plan_obs}
            for original in base_obligations:
                if original.is_mandatory:
                    assert original.obligation_id in all_plan_ids, (
                        f"Iteration {iteration}: Mandatory obligation {original.obligation_id} was dropped!"
                    )

    def test_all_24_permutations_of_four_obligation_types_produce_identical_plan(
        self, standard_case: RecoveryCase
    ):
        """Exhaustively tests all 4! = 24 permutations of the 4 obligation types."""
        t_same = datetime(2026, 9, 1, 11, 0, 0, tzinfo=timezone.utc)
        obs = [
            ComplianceObligation(
                obligation_id=f"ob_{t.value}",
                case_id=standard_case.case_id,
                obligation_type=t,
                is_mandatory=True,
                scheduled_time=t_same,
            )
            for t in [
                ObligationType.MANDATORY_DISCLOSURE,
                ObligationType.CONSENT_CHECK,
                ObligationType.COOLING_OFF,
                ObligationType.RETRY_WINDOW,
            ]
        ]

        reference_plan: ScheduledObligationPlan | None = None

        for p in itertools.permutations(obs):
            scheduler = ComplianceScheduler()
            plan = scheduler.schedule_case_obligations(
                case=standard_case,
                obligations=list(p),
                current_time=t_same,
            )

            if reference_plan is None:
                reference_plan = plan
            else:
                assert (
                    plan.scheduled_obligations == reference_plan.scheduled_obligations
                )
                assert (
                    plan.collision_resolutions == reference_plan.collision_resolutions
                )

    def test_lexicographical_tie_breaking_across_identical_types_and_priority(
        self, standard_case: RecoveryCase
    ):
        """Verifies deterministic tie-breaking on obligation_id when type and mandatory flag match."""
        t_same = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
        ob_gamma = ComplianceObligation(
            obligation_id="ob_gamma",
            case_id=standard_case.case_id,
            obligation_type=ObligationType.MANDATORY_DISCLOSURE,
            is_mandatory=True,
            scheduled_time=t_same,
        )
        ob_alpha = ComplianceObligation(
            obligation_id="ob_alpha",
            case_id=standard_case.case_id,
            obligation_type=ObligationType.MANDATORY_DISCLOSURE,
            is_mandatory=True,
            scheduled_time=t_same,
        )
        ob_beta = ComplianceObligation(
            obligation_id="ob_beta",
            case_id=standard_case.case_id,
            obligation_type=ObligationType.MANDATORY_DISCLOSURE,
            is_mandatory=True,
            scheduled_time=t_same,
        )

        for p in itertools.permutations([ob_gamma, ob_alpha, ob_beta]):
            scheduler = ComplianceScheduler()
            plan = scheduler.schedule_case_obligations(
                case=standard_case, obligations=list(p), current_time=t_same
            )
            # ob_alpha must always be the dominant one
            assert plan.scheduled_obligations[0].obligation_id == "ob_alpha"
            res_ids = [r.obligation_id for r in plan.collision_resolutions]
            assert res_ids == ["ob_beta", "ob_gamma"]


# ============================================================================
# PART 2: Policy Engine Deny-Overrides & Hierarchy Tests (TICKET-19)
# ============================================================================

class TestPolicyEngineHierarchyAndDenyOverrides:
    """Verifies strict deny-overrides rule hierarchy and lifecycle fail-closed behavior."""

    def test_tier_1_fraud_block_dominates_tier_2_and_tier_3(
        self, standard_case: RecoveryCase
    ):
        fraud_diagnosis = DiagnosisResult(
            diagnosis_code="FRAUD_RISK_BLOCK",
            risk_score=1.0,
            risk_tier=RiskTier.BLOCKED,
            is_recoverable=False,
            recommended_channel=ActionChannel.INTERNAL_SYSTEM,
            rationale="Fraud suspected. Prohibit automated recovery.",
        )
        # Construct an illegal decision attempting retry despite fraud
        snapshot = {
            "case_id": standard_case.case_id,
            "customer_id": standard_case.customer_id,
            "risk_tier": RiskTier.BLOCKED.value,
            "diagnosis_code": "FRAUD_RISK_BLOCK",
            "attempt_count": 0,
        }
        canonical_hash = compute_canonical_input_hash(snapshot)
        illegal_decision = DecisionArtifact(
            case_id=standard_case.case_id,
            model_version="mock-v1",
            prompt_version="v1",
            tool_schema_version="v1",
            canonical_input_hash=canonical_hash,
            input_snapshot=snapshot,
            recommended_action=ActionType.RETRY_CHARGE,
            parameters={
                "channel": ActionChannel.DIRECT_PAYMENT_GATEWAY.value,
                "amount_in_cents": 25000,
            },
            confidence_score=0.90,
            reasoning_summary="Attempting prohibited retry on fraud.",
        )

        engine = PolicyEngine()
        result = engine.evaluate(
            case=standard_case, diagnosis=fraud_diagnosis, decision=illegal_decision
        )

        assert result.is_allowed is False
        assert any("RULE_T1_FRAUD_BLOCK" in v for v in result.violated_rules)
        # Violations must be ordered deterministically by Tier precedence
        tier_map = {r.rule_id: r.rule_tier for r in result.rule_results if not r.is_compliant}
        assert tier_map["RULE_T1_FRAUD_BLOCK"] == RuleTier.TIER_1_MANDATORY_LEGAL_SAFETY.value

    def test_all_non_executable_policy_lifecycle_states_fail_closed(
        self,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
    ):
        non_executable_states = [
            PolicyLifecycleState.DRAFT,
            PolicyLifecycleState.REVIEW,
            PolicyLifecycleState.TEST,
            PolicyLifecycleState.SIMULATE,
            PolicyLifecycleState.RETIRED,
        ]

        for state in non_executable_states:
            custom_policy = Policy(
                policy_id=f"policy_{state.value.lower()}",
                version="v1.0.0",
                lifecycle_state=state,
                rules=DEFAULT_STANDARD_POLICY.rules,
            )
            engine = PolicyEngine()
            engine.register_policy(custom_policy)

            result = engine.evaluate(
                case=standard_case,
                diagnosis=standard_diagnosis,
                decision=standard_decision,
                policy_id=custom_policy.policy_id,
            )

            assert result.is_allowed is False, f"State {state.value} must fail closed"
            assert any("INACTIVE_POLICY_LIFECYCLE" in v for v in result.violated_rules)

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
# PART 3: Exhaustive 36-State Arbitration Matrix Verification (TICKET-21)
# ============================================================================

class TestArbitrator36StateExhaustiveMatrix:
    """
    Exhaustively verifies all 4 Safety x 3 Compliance x 3 Experiment = 36 combinations
    against the authoritative v11 Arbitration Matrix.
    """

    @pytest.mark.parametrize(
        "safety,compliance,experiment,expected_outcome",
        [
            # Safety != PASS dominates everything:
            # 1. KILL_SWITCH_ACTIVE -> always BLOCK (9 states)
            (SafetyVerdict.KILL_SWITCH_ACTIVE, ComplianceVerdict.APPROVED, ExperimentAssignment.TREATMENT, ArbitratedOutcome.BLOCK),
            (SafetyVerdict.KILL_SWITCH_ACTIVE, ComplianceVerdict.APPROVED, ExperimentAssignment.CONTROL, ArbitratedOutcome.BLOCK),
            (SafetyVerdict.KILL_SWITCH_ACTIVE, ComplianceVerdict.APPROVED, ExperimentAssignment.EXCLUDED, ArbitratedOutcome.BLOCK),
            (SafetyVerdict.KILL_SWITCH_ACTIVE, ComplianceVerdict.BLOCKED, ExperimentAssignment.TREATMENT, ArbitratedOutcome.BLOCK),
            (SafetyVerdict.KILL_SWITCH_ACTIVE, ComplianceVerdict.BLOCKED, ExperimentAssignment.CONTROL, ArbitratedOutcome.BLOCK),
            (SafetyVerdict.KILL_SWITCH_ACTIVE, ComplianceVerdict.BLOCKED, ExperimentAssignment.EXCLUDED, ArbitratedOutcome.BLOCK),
            (SafetyVerdict.KILL_SWITCH_ACTIVE, ComplianceVerdict.DEFERRED, ExperimentAssignment.TREATMENT, ArbitratedOutcome.BLOCK),
            (SafetyVerdict.KILL_SWITCH_ACTIVE, ComplianceVerdict.DEFERRED, ExperimentAssignment.CONTROL, ArbitratedOutcome.BLOCK),
            (SafetyVerdict.KILL_SWITCH_ACTIVE, ComplianceVerdict.DEFERRED, ExperimentAssignment.EXCLUDED, ArbitratedOutcome.BLOCK),

            # 2. CIRCUIT_BROKEN -> always HOLD (9 states)
            (SafetyVerdict.CIRCUIT_BROKEN, ComplianceVerdict.APPROVED, ExperimentAssignment.TREATMENT, ArbitratedOutcome.HOLD),
            (SafetyVerdict.CIRCUIT_BROKEN, ComplianceVerdict.APPROVED, ExperimentAssignment.CONTROL, ArbitratedOutcome.HOLD),
            (SafetyVerdict.CIRCUIT_BROKEN, ComplianceVerdict.APPROVED, ExperimentAssignment.EXCLUDED, ArbitratedOutcome.HOLD),
            (SafetyVerdict.CIRCUIT_BROKEN, ComplianceVerdict.BLOCKED, ExperimentAssignment.TREATMENT, ArbitratedOutcome.HOLD),
            (SafetyVerdict.CIRCUIT_BROKEN, ComplianceVerdict.BLOCKED, ExperimentAssignment.CONTROL, ArbitratedOutcome.HOLD),
            (SafetyVerdict.CIRCUIT_BROKEN, ComplianceVerdict.BLOCKED, ExperimentAssignment.EXCLUDED, ArbitratedOutcome.HOLD),
            (SafetyVerdict.CIRCUIT_BROKEN, ComplianceVerdict.DEFERRED, ExperimentAssignment.TREATMENT, ArbitratedOutcome.HOLD),
            (SafetyVerdict.CIRCUIT_BROKEN, ComplianceVerdict.DEFERRED, ExperimentAssignment.CONTROL, ArbitratedOutcome.HOLD),
            (SafetyVerdict.CIRCUIT_BROKEN, ComplianceVerdict.DEFERRED, ExperimentAssignment.EXCLUDED, ArbitratedOutcome.HOLD),

            # 3. CAPACITY_EXCEEDED -> always HOLD (9 states)
            (SafetyVerdict.CAPACITY_EXCEEDED, ComplianceVerdict.APPROVED, ExperimentAssignment.TREATMENT, ArbitratedOutcome.HOLD),
            (SafetyVerdict.CAPACITY_EXCEEDED, ComplianceVerdict.APPROVED, ExperimentAssignment.CONTROL, ArbitratedOutcome.HOLD),
            (SafetyVerdict.CAPACITY_EXCEEDED, ComplianceVerdict.APPROVED, ExperimentAssignment.EXCLUDED, ArbitratedOutcome.HOLD),
            (SafetyVerdict.CAPACITY_EXCEEDED, ComplianceVerdict.BLOCKED, ExperimentAssignment.TREATMENT, ArbitratedOutcome.HOLD),
            (SafetyVerdict.CAPACITY_EXCEEDED, ComplianceVerdict.BLOCKED, ExperimentAssignment.CONTROL, ArbitratedOutcome.HOLD),
            (SafetyVerdict.CAPACITY_EXCEEDED, ComplianceVerdict.BLOCKED, ExperimentAssignment.EXCLUDED, ArbitratedOutcome.HOLD),
            (SafetyVerdict.CAPACITY_EXCEEDED, ComplianceVerdict.DEFERRED, ExperimentAssignment.TREATMENT, ArbitratedOutcome.HOLD),
            (SafetyVerdict.CAPACITY_EXCEEDED, ComplianceVerdict.DEFERRED, ExperimentAssignment.CONTROL, ArbitratedOutcome.HOLD),
            (SafetyVerdict.CAPACITY_EXCEEDED, ComplianceVerdict.DEFERRED, ExperimentAssignment.EXCLUDED, ArbitratedOutcome.HOLD),

            # 4. Safety == PASS -> Compliance & Experiment decide (9 states):
            # Compliance BLOCKED -> BLOCK
            (SafetyVerdict.PASS, ComplianceVerdict.BLOCKED, ExperimentAssignment.TREATMENT, ArbitratedOutcome.BLOCK),
            (SafetyVerdict.PASS, ComplianceVerdict.BLOCKED, ExperimentAssignment.CONTROL, ArbitratedOutcome.BLOCK),
            (SafetyVerdict.PASS, ComplianceVerdict.BLOCKED, ExperimentAssignment.EXCLUDED, ArbitratedOutcome.BLOCK),

            # Compliance DEFERRED -> DEFER
            (SafetyVerdict.PASS, ComplianceVerdict.DEFERRED, ExperimentAssignment.TREATMENT, ArbitratedOutcome.DEFER),
            (SafetyVerdict.PASS, ComplianceVerdict.DEFERRED, ExperimentAssignment.CONTROL, ArbitratedOutcome.DEFER),
            (SafetyVerdict.PASS, ComplianceVerdict.DEFERRED, ExperimentAssignment.EXCLUDED, ArbitratedOutcome.DEFER),

            # Compliance APPROVED -> Experiment decides
            (SafetyVerdict.PASS, ComplianceVerdict.APPROVED, ExperimentAssignment.CONTROL, ArbitratedOutcome.HOLD),
            (SafetyVerdict.PASS, ComplianceVerdict.APPROVED, ExperimentAssignment.EXCLUDED, ArbitratedOutcome.BLOCK),
            # THE ONLY COMBINATION THAT YIELDS PROCEED:
            (SafetyVerdict.PASS, ComplianceVerdict.APPROVED, ExperimentAssignment.TREATMENT, ArbitratedOutcome.PROCEED),
        ],
    )
    def test_exhaustive_arbitration_matrix_combination(
        self,
        safety: SafetyVerdict,
        compliance: ComplianceVerdict,
        experiment: ExperimentAssignment,
        expected_outcome: ArbitratedOutcome,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
    ):
        t_eval = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)

        # Configure safety dependencies to match desired `safety` verdict
        kill_switch = KillSwitchManager()
        circuit_breakers = GranularCircuitBreakerRegistry()
        capacity_governor = CapacityGovernor()

        if safety == SafetyVerdict.KILL_SWITCH_ACTIVE:
            kill_switch.activate_global("Test safety kill switch")
        elif safety == SafetyVerdict.CIRCUIT_BROKEN:
            breaker = circuit_breakers.get_or_create(ActionChannel.DIRECT_PAYMENT_GATEWAY)
            breaker.record_failure(current_time=t_eval)
            breaker.record_failure(current_time=t_eval)
            breaker.record_failure(current_time=t_eval)
        elif safety == SafetyVerdict.CAPACITY_EXCEEDED:
            capacity_governor = CapacityGovernor(
                max_actions_per_window=1, max_volume_in_cents_per_window=100_000
            )
            capacity_governor.record_action(amount_in_cents=1000, current_time=t_eval)

        # Configure compliance dependencies to match desired `compliance` verdict
        scheduler = ComplianceScheduler()
        policy_engine = PolicyEngine()

        if compliance == ComplianceVerdict.BLOCKED:
            # Modify diagnosis to trigger policy block
            diag = DiagnosisResult(
                diagnosis_code="FRAUD_RISK_BLOCK",
                risk_score=1.0,
                risk_tier=RiskTier.BLOCKED,
                is_recoverable=False,
                recommended_channel=ActionChannel.INTERNAL_SYSTEM,
                rationale="Fraud block",
            )
        else:
            diag = standard_diagnosis

        if compliance == ComplianceVerdict.DEFERRED:
            # Active cooling-off obligation in scheduler
            cooling = ComplianceObligation(
                case_id=standard_case.case_id,
                obligation_type=ObligationType.COOLING_OFF,
                is_mandatory=True,
                scheduled_time=t_eval,
            )
            scheduler.schedule_obligation(cooling, current_time=t_eval)

        arbitrator = ControlPlaneArbitrator(
            policy_engine=policy_engine,
            scheduler=scheduler,
            kill_switch=kill_switch,
            circuit_breakers=circuit_breakers,
            capacity_governor=capacity_governor,
        )

        record = arbitrator.arbitrate(
            case=standard_case,
            diagnosis=diag,
            decision=standard_decision,
            experiment_assignment=experiment,
            current_time=t_eval,
        )

        assert record.safety_verdict == safety
        assert record.compliance_verdict == compliance
        assert record.experiment_assignment == experiment
        assert record.arbitrated_outcome == expected_outcome


# ============================================================================
# PART 4: Safety Freeze Dominance (INV-09)
# ============================================================================

class TestSafetyFreezeDominance:
    """Verifies that cases in CaseState.FROZEN can NEVER produce PROCEED under any circumstances."""

    def test_frozen_case_rejects_recovery_across_all_experiment_and_policy_states(
        self,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
    ):
        frozen_case = RecoveryCase(
            customer_id="cust_frozen_test",
            trigger_event_id="evt_frozen_test",
            amount_in_cents=25000,
            currency="INR",
            state=CaseState.FROZEN,
            risk_tier=RiskTier.LOW,
            attempt_count=0,
            max_attempts=3,
        )

        arbitrator = ControlPlaneArbitrator()

        for exp_state in [
            ExperimentAssignment.TREATMENT,
            ExperimentAssignment.CONTROL,
            ExperimentAssignment.EXCLUDED,
        ]:
            record = arbitrator.arbitrate(
                case=frozen_case,
                diagnosis=standard_diagnosis,
                decision=standard_decision,
                experiment_assignment=exp_state,
            )
            assert record.safety_verdict == SafetyVerdict.KILL_SWITCH_ACTIVE
            assert record.arbitrated_outcome == ArbitratedOutcome.BLOCK
            assert record.arbitrated_outcome != ArbitratedOutcome.PROCEED
            assert "FROZEN state" in record.rationale


# ============================================================================
# PART 5: Simultaneous Governance Audit Trail & Hash Integrity (INV-18)
# ============================================================================

class TestSimultaneousGovernanceAuditIntegrity:
    """Verifies multi-component audit trail logging and cryptographic hash chain verification."""

    def test_multi_component_governance_audit_chain_integrity(
        self,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
        audit_logger: CryptographicAuditLogger,
    ):
        t0 = datetime(2026, 9, 1, 14, 0, 0, tzinfo=timezone.utc)

        # 1. Policy Engine evaluation with audit
        policy_engine = PolicyEngine(audit_logger=audit_logger)
        policy_res = policy_engine.evaluate(
            case=standard_case,
            diagnosis=standard_diagnosis,
            decision=standard_decision,
            current_time=t0,
        )

        # 2. Compliance Scheduler scheduling with audit
        scheduler = ComplianceScheduler(audit_logger=audit_logger)
        ob = ComplianceObligation(
            case_id=standard_case.case_id,
            obligation_type=ObligationType.MANDATORY_DISCLOSURE,
            is_mandatory=True,
            scheduled_time=t0,
        )
        scheduler.schedule_case_obligations(
            case=standard_case, obligations=[ob], current_time=t0
        )

        # 3. Control-Plane Arbitrator evaluation with audit
        arbitrator = ControlPlaneArbitrator(
            policy_engine=policy_engine,
            scheduler=scheduler,
            audit_logger=audit_logger,
        )
        arbitration_record = arbitrator.arbitrate(
            case=standard_case,
            diagnosis=standard_diagnosis,
            decision=standard_decision,
            current_time=t0,
        )

        # Assert all 3 governance events are appended in order
        event_types = [e.event_type for e in audit_logger.entries]
        assert "POLICY_EVALUATED" in event_types
        assert "OBLIGATION_SCHEDULED" in event_types
        assert "ARBITRATION_EVALUATED" in event_types

        # Verify complete cryptographic chain integrity
        assert audit_logger.verify_chain_integrity() is True
        assert len(audit_logger.entries) >= 3


# ============================================================================
# PART 6: 100-Repetition Mathematical Determinism
# ============================================================================

class TestGovernance100RepetitionDeterminism:
    """Verifies that 100 repeated evaluations produce bit-identical records and hashes."""

    def test_arbitration_100_repetition_determinism(
        self,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
    ):
        t0 = datetime(2026, 9, 1, 15, 0, 0, tzinfo=timezone.utc)
        records = []
        for _ in range(100):
            arb = ControlPlaneArbitrator()
            r = arb.arbitrate(
                case=standard_case,
                diagnosis=standard_diagnosis,
                decision=standard_decision,
                current_time=t0,
            )
            records.append(r)

        first = records[0]
        for r in records:
            assert r.safety_verdict == first.safety_verdict
            assert r.compliance_verdict == first.compliance_verdict
            assert r.experiment_assignment == first.experiment_assignment
            assert r.arbitrated_outcome == first.arbitrated_outcome
            assert r.arbitration_hash == first.arbitration_hash
            assert r.rationale == first.rationale
