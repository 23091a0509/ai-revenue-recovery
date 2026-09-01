"""Comprehensive Verification Tests for Metric-Disappearance & Causal-Lift Governance (TICKET-28).

Authoritative Basis:
- Frozen Architecture Baseline v11 Requirements.
- engineering_backlog.md: Milestone 8, TICKET-28.
- implementation_specification.md: §1 Rules 10 & 11, §2 Boundary Matrix, §3.9 Schema, §4 Event Contracts.
- conformance_matrix.md:
  - INV-13: Backtesting never presented as causal lift.
  - INV-14: Headline metrics cannot silently disappear (Enforces required reporting states & blocking reason codes).
  - INV-11: Two-stage revenue ledger requiring settlement reconciliation.
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
def populated_rct_ledger(audit_logger: CryptographicAuditLogger) -> RevenueLedger:
    ledger = RevenueLedger(audit_logger=audit_logger)
    # Populate 20 treatment cases (18 confirmed recovered)
    for i in range(20):
        cid = f"t_case_{i:03d}"
        if i < 18:
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
    # Populate 20 control cases (6 confirmed recovered)
    for i in range(20):
        cid = f"c_case_{i:03d}"
        if i < 6:
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


# ============================================================================
# PART 1: INV-13 Verification (Backtesting vs Causal Lift)
# ============================================================================

class TestINV13CausalLiftVersusBacktesting:
    """Verifies INV-13: Backtesting must NEVER be presented as causal lift."""

    def test_backtesting_strictly_blocks_causal_lift_claim(
        self, populated_rct_ledger: RevenueLedger, audit_logger: CryptographicAuditLogger
    ):
        engine = EvidenceEngine(ledger=populated_rct_ledger, audit_logger=audit_logger)
        t_cases = [f"t_case_{i:03d}" for i in range(20)]
        c_cases = [f"c_case_{i:03d}" for i in range(20)]

        entry = engine.evaluate_window(
            metric_id="headline_recovery_rate_30d",
            evaluation_window="2026-AUG-BACKTEST",
            treatment_case_ids=t_cases,
            control_case_ids=c_cases,
            is_backtest=True,  # Strict backtesting flag
        )

        assert entry.incremental_lift is None
        assert entry.reporting_state == ReportingState.NOT_REPORTABLE
        assert BlockingReason.BACKTESTING_ONLY.value in entry.blocking_reasons

    def test_missing_control_cohort_strictly_blocks_causal_lift_claim(
        self, populated_rct_ledger: RevenueLedger, audit_logger: CryptographicAuditLogger
    ):
        engine = EvidenceEngine(ledger=populated_rct_ledger, audit_logger=audit_logger)
        t_cases = [f"t_case_{i:03d}" for i in range(20)]
        c_cases = []  # No counterfactual control group

        entry = engine.evaluate_window(
            metric_id="headline_recovery_rate_30d",
            evaluation_window="2026-AUG-NO-CTRL",
            treatment_case_ids=t_cases,
            control_case_ids=c_cases,
            is_backtest=False,
        )

        assert entry.incremental_lift is None
        assert entry.reporting_state == ReportingState.DIRECTIONAL
        assert BlockingReason.NO_EXPERIMENT_CONTROL.value in entry.blocking_reasons

    def test_valid_rct_enables_approved_causal_lift(
        self, populated_rct_ledger: RevenueLedger, audit_logger: CryptographicAuditLogger
    ):
        engine = EvidenceEngine(ledger=populated_rct_ledger, audit_logger=audit_logger)
        t_cases = [f"t_case_{i:03d}" for i in range(20)]
        c_cases = [f"c_case_{i:03d}" for i in range(20)]

        entry = engine.evaluate_window(
            metric_id="headline_recovery_rate_30d",
            evaluation_window="2026-AUG-RCT",
            treatment_case_ids=t_cases,
            control_case_ids=c_cases,
            is_backtest=False,
            min_sample_size=10,
        )

        # R_treat = 18/20 = 0.90, R_ctrl = 6/20 = 0.30 -> Lift = (0.90 - 0.30) / 0.30 = 2.0 (+200%)
        assert entry.reporting_state == ReportingState.APPROVED
        assert entry.incremental_lift is not None
        assert 1.99 <= entry.incremental_lift <= 2.01
        assert len(entry.blocking_reasons) == 0

    def test_zero_control_recovery_edge_case(self, audit_logger: CryptographicAuditLogger):
        """When control recovery is exactly 0%, lift computes relative to treatment recovery rate."""
        ledger = RevenueLedger(audit_logger=audit_logger)
        for i in range(10):
            cid = f"t_zero_ctrl_{i:03d}"
            ledger.record_gross_recovery(cid, 10000, "INR", f"exec_t_{i:03d}")
            ledger.record_confirmed_settlement(cid, 10000, 9800, "INR", f"exec_t_{i:03d}")

        engine = EvidenceEngine(ledger=ledger, audit_logger=audit_logger)
        t_cases = [f"t_zero_ctrl_{i:03d}" for i in range(10)]
        c_cases = [f"c_zero_ctrl_{i:03d}" for i in range(10)]  # 0 recoveries in control

        entry = engine.evaluate_window(
            metric_id="metric_zero_ctrl",
            evaluation_window="2026-W37",
            treatment_case_ids=t_cases,
            control_case_ids=c_cases,
            min_sample_size=10,
        )

        assert entry.reporting_state == ReportingState.APPROVED
        assert entry.incremental_lift == 1.0  # R_treat = 1.0, R_ctrl = 0.0


# ============================================================================
# PART 2: INV-14 Verification (Headline Metric Disappearance Protection)
# ============================================================================

class TestINV14MetricDisappearanceAndReportingGovernance:
    """Verifies INV-14: Headline metrics cannot silently disappear."""

    def test_metric_records_persist_in_registry_without_loss(
        self, populated_rct_ledger: RevenueLedger, audit_logger: CryptographicAuditLogger
    ):
        engine = EvidenceEngine(ledger=populated_rct_ledger, audit_logger=audit_logger)
        t_cases = [f"t_case_{i:03d}" for i in range(20)]
        c_cases = [f"c_case_{i:03d}" for i in range(20)]

        # Register multiple metrics across windows
        e1 = engine.evaluate_window("metric_alpha", "2026-W31", t_cases, c_cases)
        e2 = engine.evaluate_window("metric_alpha", "2026-W32", t_cases, c_cases)
        e3 = engine.evaluate_window("metric_beta", "2026-W31", t_cases, c_cases)

        all_entries = engine.list_metrics()
        assert len(all_entries) == 3

        # Confirm exact retrieval by composite key
        assert engine.get_evidence("metric_alpha", "2026-W31") == e1
        assert engine.get_evidence("metric_alpha", "2026-W32") == e2
        assert engine.get_evidence("metric_beta", "2026-W31") == e3

    @pytest.mark.parametrize(
        "state_name",
        ["APPROVED", "EXPERIMENTAL", "DIRECTIONAL", "NOT_REPORTABLE", "DATA_PENDING"],
    )
    def test_reporting_state_enum_completeness(self, state_name: str):
        assert state_name in ReportingState.__members__

    @pytest.mark.parametrize(
        "reason_name",
        [
            "NO_EXPERIMENT_CONTROL",
            "BACKTESTING_ONLY",
            "UNSETTLED_REVENUE",
            "HIGH_DISPUTE_RATE",
            "INSUFFICIENT_SAMPLE_SIZE",
            "DATA_WINDOW_INCOMPLETE",
        ],
    )
    def test_blocking_reason_enum_completeness(self, reason_name: str):
        assert reason_name in BlockingReason.__members__


# ============================================================================
# PART 3: INV-11 Verification (Two-Stage Revenue Recognition in Evidence)
# ============================================================================

class TestINV11TwoStageRevenueEvidenceSeparation:
    """Verifies INV-11: Gross recovered != Confirmed recovered in evidence calculation."""

    def test_gross_only_unsettled_recovery_fails_approval_to_data_pending(
        self, audit_logger: CryptographicAuditLogger
    ):
        ledger = RevenueLedger(audit_logger=audit_logger)
        # Record 15 gross recoveries without settlement reconciliation
        for i in range(15):
            ledger.record_gross_recovery(f"case_gross_{i:03d}", 10000, "INR")

        engine = EvidenceEngine(ledger=ledger, audit_logger=audit_logger)
        t_cases = [f"case_gross_{i:03d}" for i in range(10)]
        c_cases = [f"case_gross_{i:03d}" for i in range(10, 15)]

        entry = engine.evaluate_window(
            metric_id="metric_two_stage_check",
            evaluation_window="2026-W33",
            treatment_case_ids=t_cases,
            control_case_ids=c_cases,
            min_sample_size=5,
        )

        assert entry.gross_recovered == 150000
        assert entry.confirmed_recovered == 0
        assert entry.reporting_state == ReportingState.DATA_PENDING
        assert BlockingReason.UNSETTLED_REVENUE.value in entry.blocking_reasons


# ============================================================================
# PART 4: Provenance Hash & Immutability (INV-17)
# ============================================================================

class TestProvenanceHashDeterminismAndImmutability:
    """Verifies SHA-256 canonical hashing and immutable evidence models."""

    def test_100_repetition_provenance_hash_determinism(
        self, populated_rct_ledger: RevenueLedger, audit_logger: CryptographicAuditLogger
    ):
        t_cases = [f"t_case_{i:03d}" for i in range(20)]
        c_cases = [f"c_case_{i:03d}" for i in range(20)]
        t_fixed = datetime(2026, 9, 1, 15, 0, 0, tzinfo=timezone.utc)

        hashes = []
        for _ in range(100):
            eng = EvidenceEngine(ledger=populated_rct_ledger, audit_logger=audit_logger)
            entry = eng.evaluate_window(
                metric_id="metric_100_rep",
                evaluation_window="2026-DET",
                treatment_case_ids=t_cases,
                control_case_ids=c_cases,
                current_time=t_fixed,
            )
            hashes.append(entry.provenance_hash)

        assert all(h == hashes[0] for h in hashes)
        assert len(hashes[0]) == 64

    def test_evidence_metric_entry_mutation_prevented(
        self, populated_rct_ledger: RevenueLedger, audit_logger: CryptographicAuditLogger
    ):
        engine = EvidenceEngine(ledger=populated_rct_ledger, audit_logger=audit_logger)
        t_cases = [f"t_case_{i:03d}" for i in range(20)]
        c_cases = [f"c_case_{i:03d}" for i in range(20)]

        entry = engine.evaluate_window(
            metric_id="metric_freeze_test",
            evaluation_window="2026-FREEZE",
            treatment_case_ids=t_cases,
            control_case_ids=c_cases,
        )

        with pytest.raises((TypeError, ValueError)):
            entry.reporting_state = ReportingState.NOT_REPORTABLE  # type: ignore

        with pytest.raises((TypeError, ValueError)):
            entry.incremental_lift = 9.99  # type: ignore


# ============================================================================
# PART 5: INV-18 Verification (Cryptographic Audit Trail)
# ============================================================================

class TestINV18CryptographicAuditTrail:
    """Verifies INV-18: Complete audit logging of all evidence calculations."""

    def test_audit_event_emission_and_chain_integrity(
        self, populated_rct_ledger: RevenueLedger, audit_logger: CryptographicAuditLogger
    ):
        initial_count = len(audit_logger.entries)
        engine = EvidenceEngine(ledger=populated_rct_ledger, audit_logger=audit_logger)
        t_cases = [f"t_case_{i:03d}" for i in range(20)]
        c_cases = [f"c_case_{i:03d}" for i in range(20)]

        entry = engine.evaluate_window(
            metric_id="metric_audit_check",
            evaluation_window="2026-AUDIT-WIN",
            treatment_case_ids=t_cases,
            control_case_ids=c_cases,
        )

        assert len(audit_logger.entries) == initial_count + 1
        latest_audit = audit_logger.entries[-1]
        assert latest_audit.event_type == "EVIDENCE_CALCULATED"
        assert latest_audit.payload["metric_id"] == "metric_audit_check"
        assert latest_audit.payload["provenance_hash"] == entry.provenance_hash
        assert audit_logger.verify_chain_integrity() is True


# ============================================================================
# PART 6: Authority Boundaries (INV-01, INV-02)
# ============================================================================

class TestEvidenceEngineAuthorityBoundaries:
    """Verifies EvidenceEngine strictly adheres to INV-01 and INV-02."""

    def test_engine_has_zero_execution_or_authorization_methods(
        self, populated_rct_ledger: RevenueLedger, audit_logger: CryptographicAuditLogger
    ):
        engine = EvidenceEngine(ledger=populated_rct_ledger, audit_logger=audit_logger)
        forbidden_methods = [
            "execute",
            "dispatch",
            "charge",
            "send",
            "mint_token",
            "authorize",
            "create_token",
            "call_provider",
            "refund",
            "capture",
        ]
        for m in forbidden_methods:
            assert not hasattr(engine, m), f"EvidenceEngine must not expose forbidden method '{m}'"
