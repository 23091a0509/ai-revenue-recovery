"""Unit Tests for Evidence Registry and Causal Lift Engine (TICKET-27).

Authoritative Basis:
- Frozen Architecture Baseline v11 Requirements.
- INV-13: Backtesting never presented as causal lift.
- INV-14: Headline metrics cannot silently disappear (Enforces required reporting states & blocking reason codes).
- INV-11: Two-stage ledger separation of gross vs confirmed settled revenue.
- INV-18: Complete cryptographic audit logging of all calculated evidence.
- INV-01 & INV-02: Zero execution or token-minting authority.
"""

from datetime import datetime, timezone
import pytest

from src.revenue_recovery.evidence import (
    BlockingReason,
    EvidenceCalculatedEvent,
    EvidenceEngine,
    EvidenceMetricEntry,
    ReportingState,
)
from src.revenue_recovery.foundation.audit import CryptographicAuditLogger
from src.revenue_recovery.reconciliation.ledger import FinancialState, RevenueLedger


@pytest.fixture
def audit_logger() -> CryptographicAuditLogger:
    return CryptographicAuditLogger()


@pytest.fixture
def populated_ledger(audit_logger: CryptographicAuditLogger) -> RevenueLedger:
    ledger = RevenueLedger(audit_logger=audit_logger)
    # Populate 15 treatment cases with confirmed recovery
    for i in range(15):
        cid = f"case_treat_{i:03d}"
        ledger.record_gross_recovery(
            case_id=cid,
            gross_amount=10000,
            currency="INR",
            execution_id=f"exec_t_{i:03d}",
            reference=f"rec_t_{i:03d}",
        )
        ledger.record_confirmed_settlement(
            case_id=cid,
            gross_amount=10000,
            net_confirmed_amount=9800,
            currency="INR",
            execution_id=f"exec_t_{i:03d}",
            settlement_reference=f"rec_t_{i:03d}",
        )
    # Populate 15 control cases (only 5 recovered)
    for i in range(15):
        cid = f"case_ctrl_{i:03d}"
        if i < 5:
            ledger.record_gross_recovery(
                case_id=cid,
                gross_amount=10000,
                currency="INR",
                execution_id=f"exec_c_{i:03d}",
                reference=f"rec_c_{i:03d}",
            )
            ledger.record_confirmed_settlement(
                case_id=cid,
                gross_amount=10000,
                net_confirmed_amount=9800,
                currency="INR",
                execution_id=f"exec_c_{i:03d}",
                settlement_reference=f"rec_c_{i:03d}",
            )
    return ledger


@pytest.fixture
def engine(populated_ledger: RevenueLedger, audit_logger: CryptographicAuditLogger) -> EvidenceEngine:
    return EvidenceEngine(ledger=populated_ledger, audit_logger=audit_logger)


# ============================================================================
# PART 1: Valid RCT Causal Lift & Reporting State
# ============================================================================

class TestValidRCTCausalLiftCalculation:
    """Verifies causal lift computation and APPROVED reporting state for valid RCT data."""

    def test_valid_rct_evaluation_approved(self, engine: EvidenceEngine):
        t_cases = [f"case_treat_{i:03d}" for i in range(15)]
        c_cases = [f"case_ctrl_{i:03d}" for i in range(15)]

        entry = engine.evaluate_window(
            metric_id="metric_recovery_lift_30d",
            evaluation_window="2026-Q3-AUG",
            treatment_case_ids=t_cases,
            control_case_ids=c_cases,
            is_backtest=False,
            min_sample_size=10,
        )

        assert entry.metric_id == "metric_recovery_lift_30d"
        assert entry.evaluation_window == "2026-Q3-AUG"
        assert entry.reporting_state == ReportingState.APPROVED
        assert len(entry.blocking_reasons) == 0
        assert entry.treatment_count == 15
        assert entry.control_count == 15
        assert entry.treatment_recovered_count == 15
        assert entry.control_recovered_count == 5

        # R_treat = 15/15 = 1.0, R_ctrl = 5/15 = 0.3333 -> Lift = (1.0 - 0.3333)/0.3333 = 2.0
        assert entry.incremental_lift is not None
        assert 1.99 <= entry.incremental_lift <= 2.01
        assert entry.gross_recovered == 200000
        assert entry.confirmed_recovered == 196000


# ============================================================================
# PART 2: Strict INV-13 Enforcement (Backtesting & Missing Control)
# ============================================================================

class TestBacktestingAndMissingControlProhibitions:
    """Verifies strict adherence to INV-13 (Backtesting != Causal Lift)."""

    def test_backtesting_prohibits_causal_lift_and_marks_not_reportable(self, engine: EvidenceEngine):
        t_cases = [f"case_treat_{i:03d}" for i in range(15)]
        c_cases = [f"case_ctrl_{i:03d}" for i in range(15)]

        entry = engine.evaluate_window(
            metric_id="metric_backtest_sim_01",
            evaluation_window="2026-Q3-SIM",
            treatment_case_ids=t_cases,
            control_case_ids=c_cases,
            is_backtest=True,  # Backtesting flag
        )

        assert entry.incremental_lift is None
        assert entry.reporting_state == ReportingState.NOT_REPORTABLE
        assert BlockingReason.BACKTESTING_ONLY.value in entry.blocking_reasons

    def test_missing_control_cohort_prohibits_causal_lift(self, engine: EvidenceEngine):
        t_cases = [f"case_treat_{i:03d}" for i in range(15)]
        c_cases = []  # No control group

        entry = engine.evaluate_window(
            metric_id="metric_observational_only",
            evaluation_window="2026-Q3-OBS",
            treatment_case_ids=t_cases,
            control_case_ids=c_cases,
            is_backtest=False,
        )

        assert entry.incremental_lift is None
        assert entry.reporting_state == ReportingState.DIRECTIONAL
        assert BlockingReason.NO_EXPERIMENT_CONTROL.value in entry.blocking_reasons


# ============================================================================
# PART 3: Insufficient Sample Size & Two-Stage Revenue (INV-11)
# ============================================================================

class TestSampleBoundsAndTwoStageRevenue:
    """Verifies sample size bounds and gross vs confirmed revenue handling (INV-11)."""

    def test_insufficient_sample_size_marks_data_pending(self, engine: EvidenceEngine):
        t_cases = ["case_treat_001", "case_treat_002"]
        c_cases = ["case_ctrl_001", "case_ctrl_002"]

        entry = engine.evaluate_window(
            metric_id="metric_small_sample",
            evaluation_window="2026-W35",
            treatment_case_ids=t_cases,
            control_case_ids=c_cases,
            min_sample_size=10,  # Required 10, got 2
        )

        assert entry.reporting_state == ReportingState.DATA_PENDING
        assert BlockingReason.INSUFFICIENT_SAMPLE_SIZE.value in entry.blocking_reasons

    def test_unsettled_revenue_marks_data_pending(self, audit_logger: CryptographicAuditLogger):
        unsettled_ledger = RevenueLedger(audit_logger=audit_logger)
        # 15 cases with gross only, 0 confirmed
        for i in range(15):
            unsettled_ledger.record_gross_recovery(
                case_id=f"case_unsettled_{i:03d}",
                gross_amount=5000,
                currency="INR",
                execution_id=f"exec_u_{i:03d}",
                reference=f"rec_u_{i:03d}",
            )
        eng = EvidenceEngine(ledger=unsettled_ledger, audit_logger=audit_logger)

        t_cases = [f"case_unsettled_{i:03d}" for i in range(10)]
        c_cases = [f"case_unsettled_{i:03d}" for i in range(10, 15)]

        entry = eng.evaluate_window(
            metric_id="metric_unsettled",
            evaluation_window="2026-W36",
            treatment_case_ids=t_cases,
            control_case_ids=c_cases,
            min_sample_size=5,
        )

        assert entry.gross_recovered > 0
        assert entry.confirmed_recovered == 0
        assert entry.reporting_state == ReportingState.DATA_PENDING
        assert BlockingReason.UNSETTLED_REVENUE.value in entry.blocking_reasons


# ============================================================================
# PART 4: Provenance Hash, Immutability & Retrieval (INV-14, INV-17)
# ============================================================================

class TestProvenanceHashAndRegistryRetrieval:
    """Verifies deterministic SHA-256 provenance hashing and registry retrieval."""

    def test_provenance_hash_is_deterministic_and_sha256(self, engine: EvidenceEngine):
        t_cases = [f"case_treat_{i:03d}" for i in range(15)]
        c_cases = [f"case_ctrl_{i:03d}" for i in range(15)]
        t_fixed = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)

        hashes = [
            engine.evaluate_window(
                metric_id="metric_det_hash",
                evaluation_window="2026-DET",
                treatment_case_ids=t_cases,
                control_case_ids=c_cases,
                current_time=t_fixed,
            ).provenance_hash
            for _ in range(10)
        ]

        assert len(set(hashes)) == 1
        assert len(hashes[0]) == 64

    def test_get_evidence_and_list_metrics(self, engine: EvidenceEngine):
        t_cases = [f"case_treat_{i:03d}" for i in range(15)]
        c_cases = [f"case_ctrl_{i:03d}" for i in range(15)]

        entry = engine.evaluate_window(
            metric_id="metric_registry_test",
            evaluation_window="2026-REG",
            treatment_case_ids=t_cases,
            control_case_ids=c_cases,
        )

        fetched = engine.get_evidence("metric_registry_test", "2026-REG")
        assert fetched is not None
        assert fetched.provenance_hash == entry.provenance_hash

        all_metrics = engine.list_metrics()
        assert any(m.metric_id == "metric_registry_test" for m in all_metrics)

    def test_metric_entry_is_immutable(self, engine: EvidenceEngine):
        t_cases = [f"case_treat_{i:03d}" for i in range(15)]
        c_cases = [f"case_ctrl_{i:03d}" for i in range(15)]

        entry = engine.evaluate_window(
            metric_id="metric_immut_test",
            evaluation_window="2026-IMMUT",
            treatment_case_ids=t_cases,
            control_case_ids=c_cases,
        )

        with pytest.raises((TypeError, ValueError)):
            entry.reporting_state = ReportingState.NOT_REPORTABLE  # type: ignore


# ============================================================================
# PART 5: Audit Event Emission & Hash Chain (INV-18)
# ============================================================================

class TestAuditEventEmissionAndChainIntegrity:
    """Verifies EVIDENCE_CALCULATED event recording and audit chain integrity."""

    def test_audit_event_recorded_and_chain_valid(
        self, engine: EvidenceEngine, audit_logger: CryptographicAuditLogger
    ):
        initial_entries_count = len(audit_logger.entries)
        t_cases = [f"case_treat_{i:03d}" for i in range(15)]
        c_cases = [f"case_ctrl_{i:03d}" for i in range(15)]

        entry = engine.evaluate_window(
            metric_id="metric_audit_eval",
            evaluation_window="2026-AUDIT",
            treatment_case_ids=t_cases,
            control_case_ids=c_cases,
        )

        assert len(audit_logger.entries) == initial_entries_count + 1
        latest_audit = audit_logger.entries[-1]
        assert latest_audit.event_type == "EVIDENCE_CALCULATED"
        assert latest_audit.payload["metric_id"] == "metric_audit_eval"
        exp_rep_state = entry.reporting_state.value if isinstance(entry.reporting_state, ReportingState) else str(entry.reporting_state)
        assert latest_audit.payload["reporting_state"] == exp_rep_state
        assert latest_audit.payload["provenance_hash"] == entry.provenance_hash
        assert audit_logger.verify_chain_integrity() is True


# ============================================================================
# PART 6: Authority Boundaries (INV-01, INV-02)
# ============================================================================

class TestEvidenceEngineAuthorityBoundaries:
    """Verifies EvidenceEngine contains zero execution or token-minting authority."""

    def test_engine_has_no_execution_or_authorization_methods(self, engine: EvidenceEngine):
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
            assert not hasattr(engine, m), f"EvidenceEngine must not expose '{m}'"
