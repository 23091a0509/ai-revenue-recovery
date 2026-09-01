"""Unit Tests for Randomized Controlled Experiment Stratification and Assignment Engine (TICKET-26).

Authoritative Basis:
- Frozen Architecture Baseline v11 Requirements.
- INV-01: AI recommends; it does not execute.
- INV-02: Least-privilege authority boundaries (Evidence/Experiment engine with zero execution/token-minting authority).
- INV-13: Backtesting never presented as causal lift (Requires randomized controlled experiment logs for counterfactual baseline).
- INV-18: Complete audit logging of all assignments via append-only cryptographic logger.
"""

from datetime import datetime, timezone
import pytest

from src.revenue_recovery.evidence import (
    ExperimentAssignment,
    ExperimentAssignmentRecord,
    ExperimentAssignedEvent,
    ExperimentConfig,
    ExperimentEngine,
    StratumKey,
)
from src.revenue_recovery.foundation.audit import CryptographicAuditLogger
from src.revenue_recovery.foundation.events import CaseState, RecoveryCase, RiskTier


@pytest.fixture
def audit_logger() -> CryptographicAuditLogger:
    return CryptographicAuditLogger()


@pytest.fixture
def engine(audit_logger: CryptographicAuditLogger) -> ExperimentEngine:
    return ExperimentEngine(audit_logger=audit_logger)


@pytest.fixture
def sample_case() -> RecoveryCase:
    return RecoveryCase(
        case_id="case_exp_test_001",
        customer_id="cust_exp_9988",
        trigger_event_id="evt_trig_9988",
        amount_in_cents=50000,
        currency="INR",
        state=CaseState.EVALUATING,
        risk_tier=RiskTier.LOW,
    )


# ============================================================================
# PART 1: Configuration Validation & Immutability
# ============================================================================

class TestExperimentConfigValidation:
    """Verifies ExperimentConfig validation rules and immutability."""

    def test_valid_experiment_config(self):
        config = ExperimentConfig(
            experiment_id="exp_promo_2026",
            name="Promo Recovery 2026",
            treatment_ratio=0.70,
            control_ratio=0.20,
            excluded_ratio=0.10,
            salt="promo_salt_abc",
        )
        assert config.experiment_id == "exp_promo_2026"
        assert config.treatment_ratio == 0.70
        assert config.control_ratio == 0.20
        assert config.excluded_ratio == 0.10
        assert config.is_active is True

    def test_ratios_not_summing_to_one_rejected(self):
        with pytest.raises(ValueError, match="must sum to 1.0"):
            ExperimentConfig(
                experiment_id="exp_bad_sum",
                name="Bad Sum",
                treatment_ratio=0.50,
                control_ratio=0.20,
                excluded_ratio=0.10,  # Sum = 0.80 != 1.0
            )

    def test_negative_ratio_rejected(self):
        with pytest.raises(ValueError):
            ExperimentConfig(
                experiment_id="exp_neg_ratio",
                name="Negative Ratio",
                treatment_ratio=-0.10,
                control_ratio=0.60,
                excluded_ratio=0.50,
            )

    def test_config_immutability(self):
        config = ExperimentConfig(
            experiment_id="exp_immut",
            name="Immutable Config",
            treatment_ratio=0.80,
            control_ratio=0.10,
            excluded_ratio=0.10,
        )
        with pytest.raises((TypeError, ValueError)):
            config.treatment_ratio = 0.50  # type: ignore


# ============================================================================
# PART 2: Deterministic Bucket Scoring & Stratification
# ============================================================================

class TestDeterministicStratificationAndHashing:
    """Verifies SHA-256 deterministic bucket scoring and stratification keys."""

    def test_stratum_canonical_string(self):
        stratum = StratumKey(risk_tier=RiskTier.HIGH, currency="USD", failure_code="insufficient_funds")
        assert stratum.to_canonical_str() == "HIGH:USD:INSUFFICIENT_FUNDS"

        stratum_none_code = StratumKey(risk_tier=RiskTier.LOW, currency="INR", failure_code=None)
        assert stratum_none_code.to_canonical_str() == "LOW:INR:NONE"

    def test_bucket_score_is_in_zero_to_one_range(self, engine: ExperimentEngine):
        score = engine.compute_bucket_score(
            salt="test_salt",
            experiment_id="exp_01",
            customer_id="cust_12345",
            stratum="LOW:INR:NONE",
        )
        assert 0.0 <= score < 1.0

    def test_100_repetition_bucket_score_determinism(self, engine: ExperimentEngine):
        scores = [
            engine.compute_bucket_score(
                salt="salt_fixed_v1",
                experiment_id="exp_det_100",
                customer_id="cust_stable_007",
                stratum="MEDIUM:USD:DO_NOT_HONOR",
            )
            for _ in range(100)
        ]
        assert all(s == scores[0] for s in scores)

    def test_different_salt_changes_bucket_score(self, engine: ExperimentEngine):
        s1 = engine.compute_bucket_score("salt_A", "exp_01", "cust_1", "LOW:INR:NONE")
        s2 = engine.compute_bucket_score("salt_B", "exp_01", "cust_1", "LOW:INR:NONE")
        assert s1 != s2


# ============================================================================
# PART 3: Arm Assignments (TREATMENT, CONTROL, EXCLUDED)
# ============================================================================

class TestExperimentArmAssignments:
    """Verifies assignment to TREATMENT, CONTROL, and EXCLUDED based on ratio boundaries."""

    def test_all_three_arms_reachable(self, engine: ExperimentEngine):
        """Generates multiple customers to verify reaching all three experiment arms."""
        assigned_arms = set()
        for i in range(100):
            case = RecoveryCase(
                case_id=f"case_arm_test_{i:03d}",
                customer_id=f"customer_arm_{i:03d}",
                trigger_event_id=f"evt_arm_{i:03d}",
                amount_in_cents=10000,
                currency="INR",
                state=CaseState.EVALUATING,
                risk_tier=RiskTier.LOW,
            )
            rec = engine.assign(case)
            assigned_arms.add(rec.assignment)

        assert ExperimentAssignment.TREATMENT in assigned_arms
        assert ExperimentAssignment.CONTROL in assigned_arms
        assert ExperimentAssignment.EXCLUDED in assigned_arms

    def test_100_percent_treatment_experiment(self, engine: ExperimentEngine, sample_case: RecoveryCase):
        cfg = ExperimentConfig(
            experiment_id="exp_100_treat",
            name="100% Treatment",
            treatment_ratio=1.0,
            control_ratio=0.0,
            excluded_ratio=0.0,
        )
        engine.register_experiment(cfg)
        rec = engine.assign(sample_case, experiment_id="exp_100_treat")
        assert rec.assignment == ExperimentAssignment.TREATMENT

    def test_100_percent_control_experiment(self, engine: ExperimentEngine, sample_case: RecoveryCase):
        cfg = ExperimentConfig(
            experiment_id="exp_100_ctrl",
            name="100% Control",
            treatment_ratio=0.0,
            control_ratio=1.0,
            excluded_ratio=0.0,
        )
        engine.register_experiment(cfg)
        rec = engine.assign(sample_case, experiment_id="exp_100_ctrl")
        assert rec.assignment == ExperimentAssignment.CONTROL

    def test_100_percent_excluded_experiment(self, engine: ExperimentEngine, sample_case: RecoveryCase):
        cfg = ExperimentConfig(
            experiment_id="exp_100_excl",
            name="100% Excluded",
            treatment_ratio=0.0,
            control_ratio=0.0,
            excluded_ratio=1.0,
        )
        engine.register_experiment(cfg)
        rec = engine.assign(sample_case, experiment_id="exp_100_excl")
        assert rec.assignment == ExperimentAssignment.EXCLUDED


# ============================================================================
# PART 4: Assignment Idempotency & Retrieval
# ============================================================================

class TestAssignmentRetrievalAndIdempotency:
    """Verifies repeated assignments return cached records and retrieval by case_id."""

    def test_repeated_assign_returns_identical_record(self, engine: ExperimentEngine, sample_case: RecoveryCase):
        t1 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 9, 1, 10, 5, 0, tzinfo=timezone.utc)

        r1 = engine.assign(sample_case, current_time=t1)
        r2 = engine.assign(sample_case, current_time=t2)

        assert r1.assignment_id == r2.assignment_id
        assert r1.bucket_score == r2.bucket_score
        assert r1.assignment == r2.assignment
        assert r1.assigned_at == t1

    def test_get_assignment_for_case(self, engine: ExperimentEngine, sample_case: RecoveryCase):
        assert engine.get_assignment_for_case(sample_case.case_id) is None

        rec = engine.assign(sample_case)
        fetched = engine.get_assignment_for_case(sample_case.case_id)

        assert fetched is not None
        assert fetched.assignment_id == rec.assignment_id
        assert fetched.case_id == sample_case.case_id

    def test_inactive_experiment_raises_value_error(self, engine: ExperimentEngine, sample_case: RecoveryCase):
        cfg = ExperimentConfig(
            experiment_id="exp_inactive_01",
            name="Inactive Experiment",
            treatment_ratio=0.80,
            control_ratio=0.10,
            excluded_ratio=0.10,
            is_active=False,
        )
        engine.register_experiment(cfg)
        with pytest.raises(ValueError, match="is inactive and cannot accept assignments"):
            engine.assign(sample_case, experiment_id="exp_inactive_01")

    def test_unregistered_experiment_raises_key_error(self, engine: ExperimentEngine, sample_case: RecoveryCase):
        with pytest.raises(KeyError, match="is not registered"):
            engine.assign(sample_case, experiment_id="exp_non_existent")


# ============================================================================
# PART 5: Audit Trail (INV-18) & Determinism
# ============================================================================

class TestExperimentAuditAndDeterminism:
    """Verifies audit event emission (INV-18) and 100-repetition determinism."""

    def test_audit_logger_records_experiment_assigned_event(
        self, engine: ExperimentEngine, sample_case: RecoveryCase, audit_logger: CryptographicAuditLogger
    ):
        t_assigned = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
        rec = engine.assign(sample_case, current_time=t_assigned)

        assert len(audit_logger.entries) == 1
        entry = audit_logger.entries[0]
        assert entry.event_type == "EXPERIMENT_ASSIGNED"
        assert entry.payload["case_id"] == sample_case.case_id
        exp_val = rec.assignment.value if isinstance(rec.assignment, ExperimentAssignment) else str(rec.assignment)
        assert entry.payload["assignment"] == exp_val
        assert entry.payload["bucket_score"] == rec.bucket_score
        assert audit_logger.verify_chain_integrity() is True

    def test_100_repetition_engine_assignment_determinism(self, sample_case: RecoveryCase):
        t_fixed = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
        records = []
        for _ in range(100):
            eng = ExperimentEngine()
            rec = eng.assign(sample_case, current_time=t_fixed)
            records.append(rec)

        first = records[0]
        for r in records:
            assert r.experiment_id == first.experiment_id
            assert r.case_id == first.case_id
            assert r.customer_id == first.customer_id
            assert r.stratum == first.stratum
            assert r.assignment == first.assignment
            assert r.bucket_score == first.bucket_score


# ============================================================================
# PART 6: Authority Boundaries (INV-01, INV-02)
# ============================================================================

class TestExperimentAuthorityBoundaries:
    """Verifies ExperimentEngine has zero execution or authorization methods."""

    def test_engine_has_no_execution_or_authorization_methods(self, engine: ExperimentEngine):
        forbidden_methods = [
            "execute",
            "dispatch",
            "charge",
            "send",
            "mint_token",
            "authorize",
            "create_token",
            "call_provider",
        ]
        for m in forbidden_methods:
            assert not hasattr(engine, m), f"ExperimentEngine must not expose '{m}'"
