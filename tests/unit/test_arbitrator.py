"""Comprehensive Unit and Safety Tests for Control-Plane Arbitrator (TICKET-21).

Authoritative Basis:
- Frozen Architecture Baseline v11 Requirements.
- INV-01: AI recommends; it does not execute.
- INV-02: Least-privilege authority boundaries (Arbitrator evaluates; zero execution/minting).
- INV-09: Safety freezes cannot be bypassed via retry.
- INV-18: Complete audit logging of arbitration evaluations.

Enforces:
1. Safety coordination (KillSwitch, CircuitBreaker, CapacityGovernor, CaseState.FROZEN).
2. Compliance coordination (PolicyEngine, ComplianceScheduler).
3. Experiment stratification (Treatment vs Control Holdback vs Excluded).
4. Deterministic Arbitration Matrix precedence.
5. Verifiable SHA-256 canonical arbitration hash.
6. Immutability of arbitration records and events.
7. Append-only cryptographic audit logging.
8. 100-repetition mathematical determinism.
"""

from datetime import datetime, timezone
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
    PolicyEngine,
    SafetyVerdict,
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
        customer_id="cust_arb_001",
        trigger_event_id="evt_arb_001",
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
        diagnosis_code="INSUFFICIENT_FUNDS_TRANSIENT",
        risk_score=0.15,
        risk_tier=RiskTier.LOW,
        is_recoverable=True,
        recommended_channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
        rationale="Initial transient decline. Eligible for automated retry.",
    )


@pytest.fixture
def standard_decision(standard_case: RecoveryCase, standard_diagnosis: DiagnosisResult) -> DecisionArtifact:
    return create_decision_artifact(case=standard_case, diagnosis=standard_diagnosis)


# ============================================================================
# PART 1: Core Happy Path & Full Pass (PROCEED)
# ============================================================================

class TestArbitratorHappyPath:
    """Verifies that when all safety, compliance, and experiment gates pass, outcome is PROCEED."""

    def test_full_pass_treatment_returns_proceed(
        self,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
    ):
        arbitrator = ControlPlaneArbitrator()
        record = arbitrator.arbitrate(
            case=standard_case,
            diagnosis=standard_diagnosis,
            decision=standard_decision,
            experiment_assignment=ExperimentAssignment.TREATMENT,
        )

        assert record.safety_verdict == SafetyVerdict.PASS
        assert record.compliance_verdict == ComplianceVerdict.APPROVED
        assert record.experiment_assignment == ExperimentAssignment.TREATMENT
        assert record.arbitrated_outcome == ArbitratedOutcome.PROCEED
        assert len(record.arbitration_hash) == 64
        assert "All governance gates passed" in record.rationale


# ============================================================================
# PART 2: Safety Gates (KillSwitch, CircuitBreaker, Capacity, Case Freeze)
# ============================================================================

class TestArbitratorSafetyGates:
    """Verifies that safety trips dominate lower-level decisions."""

    def test_kill_switch_active_returns_block(
        self,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
    ):
        kill_switch = KillSwitchManager()
        kill_switch.activate_global("Global emergency halt")

        arbitrator = ControlPlaneArbitrator(kill_switch=kill_switch)
        record = arbitrator.arbitrate(
            case=standard_case,
            diagnosis=standard_diagnosis,
            decision=standard_decision,
        )

        assert record.safety_verdict == SafetyVerdict.KILL_SWITCH_ACTIVE
        assert record.arbitrated_outcome == ArbitratedOutcome.BLOCK
        assert "Kill switch active" in record.rationale

    def test_circuit_breaker_open_returns_hold(
        self,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
    ):
        circuit_breakers = GranularCircuitBreakerRegistry()
        breaker = circuit_breakers.get_or_create(ActionChannel.DIRECT_PAYMENT_GATEWAY)
        # Trip breaker to OPEN
        breaker.record_failure()
        breaker.record_failure()
        breaker.record_failure()

        arbitrator = ControlPlaneArbitrator(circuit_breakers=circuit_breakers)
        record = arbitrator.arbitrate(
            case=standard_case,
            diagnosis=standard_diagnosis,
            decision=standard_decision,
        )

        assert record.safety_verdict == SafetyVerdict.CIRCUIT_BROKEN
        assert record.arbitrated_outcome == ArbitratedOutcome.HOLD
        assert "Circuit breaker" in record.rationale

    def test_capacity_exceeded_returns_hold(
        self,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
    ):
        capacity_governor = CapacityGovernor(
            max_actions_per_window=1,
            max_volume_in_cents_per_window=100_000,
        )
        # Saturate capacity
        capacity_governor.record_action(amount_in_cents=1000)

        arbitrator = ControlPlaneArbitrator(capacity_governor=capacity_governor)
        record = arbitrator.arbitrate(
            case=standard_case,
            diagnosis=standard_diagnosis,
            decision=standard_decision,
        )

        assert record.safety_verdict == SafetyVerdict.CAPACITY_EXCEEDED
        assert record.arbitrated_outcome == ArbitratedOutcome.HOLD
        assert "Action rate limit exceeded" in record.rationale

    def test_frozen_case_safety_freeze_returns_kill_switch_active_block(
        self,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
    ):
        frozen_case = RecoveryCase(
            customer_id="cust_frozen_999",
            trigger_event_id="evt_frozen_999",
            amount_in_cents=25000,
            currency="INR",
            state=CaseState.FROZEN,
            risk_tier=RiskTier.HIGH,
            attempt_count=1,
            max_attempts=3,
        )

        arbitrator = ControlPlaneArbitrator()
        record = arbitrator.arbitrate(
            case=frozen_case,
            diagnosis=standard_diagnosis,
            decision=standard_decision,
        )

        assert record.safety_verdict == SafetyVerdict.KILL_SWITCH_ACTIVE
        assert record.arbitrated_outcome == ArbitratedOutcome.BLOCK
        assert "FROZEN" in record.rationale


# ============================================================================
# PART 3: Compliance Gates (Policy Engine & Compliance Scheduler)
# ============================================================================

class TestArbitratorComplianceGates:
    """Verifies policy rejection (BLOCK) and scheduler deferral (DEFER)."""

    def test_policy_rejection_returns_compliance_block(
        self,
        standard_case: RecoveryCase,
        standard_decision: DecisionArtifact,
    ):
        fraud_diagnosis = DiagnosisResult(
            diagnosis_code="FRAUD_RISK_BLOCK",
            risk_score=1.0,
            risk_tier=RiskTier.BLOCKED,
            is_recoverable=False,
            recommended_channel=ActionChannel.INTERNAL_SYSTEM,
            rationale="Fraud suspected. Prohibit automated recovery.",
        )

        arbitrator = ControlPlaneArbitrator()
        record = arbitrator.arbitrate(
            case=standard_case,
            diagnosis=fraud_diagnosis,
            decision=standard_decision,
        )

        assert record.safety_verdict == SafetyVerdict.PASS
        assert record.compliance_verdict == ComplianceVerdict.BLOCKED
        assert record.arbitrated_outcome == ArbitratedOutcome.BLOCK
        assert "Policy Engine rejected decision" in record.rationale

    def test_pending_cooling_off_obligation_returns_compliance_defer(
        self,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
    ):
        scheduler = ComplianceScheduler()
        t_future = datetime(2026, 9, 1, 14, 0, 0, tzinfo=timezone.utc)
        cooling_ob = ComplianceObligation(
            case_id=standard_case.case_id,
            obligation_type=ObligationType.COOLING_OFF,
            is_mandatory=True,
            scheduled_time=t_future,
        )
        scheduler.schedule_obligation(cooling_ob)

        arbitrator = ControlPlaneArbitrator(scheduler=scheduler)
        record = arbitrator.arbitrate(
            case=standard_case,
            diagnosis=standard_diagnosis,
            decision=standard_decision,
            current_time=t_future,
        )

        assert record.safety_verdict == SafetyVerdict.PASS
        assert record.compliance_verdict == ComplianceVerdict.DEFERRED
        assert record.arbitrated_outcome == ArbitratedOutcome.DEFER
        assert "Compliance obligation 'COOLING_OFF'" in record.rationale


# ============================================================================
# PART 4: Experiment Stratification Gates (CONTROL & EXCLUDED)
# ============================================================================

class TestArbitratorExperimentGates:
    """Verifies control holdback (HOLD) and exclusion (BLOCK)."""

    def test_control_assignment_returns_hold(
        self,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
    ):
        arbitrator = ControlPlaneArbitrator()
        record = arbitrator.arbitrate(
            case=standard_case,
            diagnosis=standard_diagnosis,
            decision=standard_decision,
            experiment_assignment=ExperimentAssignment.CONTROL,
        )

        assert record.safety_verdict == SafetyVerdict.PASS
        assert record.compliance_verdict == ComplianceVerdict.APPROVED
        assert record.experiment_assignment == ExperimentAssignment.CONTROL
        assert record.arbitrated_outcome == ArbitratedOutcome.HOLD
        assert "CONTROL group counterfactual baseline" in record.rationale

    def test_excluded_assignment_returns_block(
        self,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
    ):
        arbitrator = ControlPlaneArbitrator()
        record = arbitrator.arbitrate(
            case=standard_case,
            diagnosis=standard_diagnosis,
            decision=standard_decision,
            experiment_assignment=ExperimentAssignment.EXCLUDED,
        )

        assert record.safety_verdict == SafetyVerdict.PASS
        assert record.compliance_verdict == ComplianceVerdict.APPROVED
        assert record.experiment_assignment == ExperimentAssignment.EXCLUDED
        assert record.arbitrated_outcome == ArbitratedOutcome.BLOCK
        assert "EXCLUDED from automated recovery" in record.rationale


# ============================================================================
# PART 5: Precedence, Immutability, Audit Trail & Determinism
# ============================================================================

class TestArbitratorPrecedenceAuditAndDeterminism:
    """Verifies strict cross-loop precedence, audit trail integrity, and 100-repetition determinism."""

    def test_safety_dominates_over_compliance_and_experiment(
        self,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
    ):
        # Kill switch is active AND experiment is CONTROL
        kill_switch = KillSwitchManager()
        kill_switch.activate_global("Emergency freeze")

        arbitrator = ControlPlaneArbitrator(kill_switch=kill_switch)
        record = arbitrator.arbitrate(
            case=standard_case,
            diagnosis=standard_diagnosis,
            decision=standard_decision,
            experiment_assignment=ExperimentAssignment.CONTROL,
        )

        # Safety dominates: must be KILL_SWITCH_ACTIVE -> BLOCK (not HOLD from CONTROL)
        assert record.safety_verdict == SafetyVerdict.KILL_SWITCH_ACTIVE
        assert record.arbitrated_outcome == ArbitratedOutcome.BLOCK

    def test_canonical_arbitration_hash_reproducibility(self):
        payload1 = {"case_id": "c1", "safety_verdict": "PASS", "arbitrated_outcome": "PROCEED"}
        payload2 = {"arbitrated_outcome": "PROCEED", "case_id": "c1", "safety_verdict": "PASS"}

        h1 = compute_canonical_arbitration_hash(payload1)
        h2 = compute_canonical_arbitration_hash(payload2)

        assert h1 == h2
        assert len(h1) == 64

    def test_audit_logger_records_arbitration_evaluated_event(
        self,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
        audit_logger: CryptographicAuditLogger,
    ):
        t0 = datetime(2026, 9, 1, 15, 0, 0, tzinfo=timezone.utc)
        arbitrator = ControlPlaneArbitrator(audit_logger=audit_logger)

        record = arbitrator.arbitrate(
            case=standard_case,
            diagnosis=standard_diagnosis,
            decision=standard_decision,
            current_time=t0,
        )

        assert len(audit_logger.entries) >= 1
        entry = audit_logger.entries[0]
        assert entry.event_type == "ARBITRATION_EVALUATED"
        assert entry.payload["case_id"] == standard_case.case_id
        assert entry.payload["arbitration_id"] == record.arbitration_id
        assert entry.payload["verdict"] == ArbitratedOutcome.PROCEED.value
        assert entry.payload["experiment_state"] == ExperimentAssignment.TREATMENT.value
        assert entry.payload["arbitration_hash"] == record.arbitration_hash
        assert entry.timestamp == t0

        # Verify cryptographic chain integrity
        assert audit_logger.verify_chain_integrity() is True

    def test_100_repetition_determinism(
        self,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
    ):
        t0 = datetime(2026, 9, 1, 16, 0, 0, tzinfo=timezone.utc)
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

    def test_immutability_of_record_and_event(
        self,
        standard_case: RecoveryCase,
        standard_diagnosis: DiagnosisResult,
        standard_decision: DecisionArtifact,
    ):
        arbitrator = ControlPlaneArbitrator()
        record = arbitrator.arbitrate(
            case=standard_case,
            diagnosis=standard_diagnosis,
            decision=standard_decision,
        )

        with pytest.raises((ValidationError, TypeError)):
            record.arbitrated_outcome = ArbitratedOutcome.BLOCK  # type: ignore

        event = ArbitrationEvaluatedEvent(
            case_id=standard_case.case_id,
            arbitration_id=record.arbitration_id,
            verdict=str(record.arbitrated_outcome),
            experiment_state=str(record.experiment_assignment),
            arbitration_hash=record.arbitration_hash,
        )
        with pytest.raises((ValidationError, TypeError)):
            event.verdict = "MUTATED"  # type: ignore


# ============================================================================
# PART 6: Authority & Capability Boundaries (INV-01, INV-02)
# ============================================================================

class TestControlPlaneArbitratorAuthorityBoundaries:
    """Verifies that ControlPlaneArbitrator has zero execution or token-minting methods."""

    def test_arbitrator_has_no_execution_or_minting_methods(self):
        arbitrator = ControlPlaneArbitrator()
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
            assert not hasattr(arbitrator, method_name), f"ControlPlaneArbitrator must NOT have method '{method_name}'"
