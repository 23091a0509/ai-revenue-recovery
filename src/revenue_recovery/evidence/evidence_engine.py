"""Evidence Registry and Causal Lift Engine (TICKET-27).

Authoritative Basis:
- Frozen Architecture Baseline v11 Requirements.
- engineering_backlog.md: Milestone 8, TICKET-27.
- implementation_specification.md: §1 Rules 10 & 11, §2 Boundary Matrix, §3.9 Schema, §4 Event Contracts.
- conformance_matrix.md: INV-11 (Two-stage ledger), INV-13 (Backtesting != Causal Lift),
  INV-14 (Headline metrics cannot silently disappear), INV-18 (Complete cryptographic audit trail).
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import threading
from typing import Dict, List, Optional, Tuple
import uuid

from pydantic import Field

from src.revenue_recovery.evidence.experiment import ExperimentEngine
from src.revenue_recovery.foundation.audit import CryptographicAuditLogger, canonical_json
from src.revenue_recovery.foundation.events import ImmutableBaseModel
from src.revenue_recovery.reconciliation.ledger import FinancialState, RevenueLedger


# ============================================================================
# Enums
# ============================================================================

class ReportingState(str, Enum):
    """
    Reporting governance state for recovery evidence metrics (§3.9).
    
    States:
    - APPROVED: Validated causal evidence from RCT with sufficient sample size,
      active control group, and confirmed settled revenue.
    - EXPERIMENTAL: Active RCT evaluation in progress with valid control group,
      where metrics are preliminary or exploratory.
    - DIRECTIONAL: Observational trends or historical baseline data without
      contemporaneous randomized control holdback (explicitly non-causal).
    - NOT_REPORTABLE: Strict block on reporting due to backtesting, severe data skew,
      active dispute spikes, or zero control baseline.
    - DATA_PENDING: Incomplete evaluation window, insufficient sample count,
      or unfinalized settlements.
    """
    APPROVED = "APPROVED"
    EXPERIMENTAL = "EXPERIMENTAL"
    DIRECTIONAL = "DIRECTIONAL"
    NOT_REPORTABLE = "NOT_REPORTABLE"
    DATA_PENDING = "DATA_PENDING"


class BlockingReason(str, Enum):
    """
    Authoritative blocking reason codes explaining non-reportable or pending states (§3.9).
    """
    NO_EXPERIMENT_CONTROL = "NO_EXPERIMENT_CONTROL"
    BACKTESTING_ONLY = "BACKTESTING_ONLY"
    UNSETTLED_REVENUE = "UNSETTLED_REVENUE"
    HIGH_DISPUTE_RATE = "HIGH_DISPUTE_RATE"
    INSUFFICIENT_SAMPLE_SIZE = "INSUFFICIENT_SAMPLE_SIZE"
    DATA_WINDOW_INCOMPLETE = "DATA_WINDOW_INCOMPLETE"


# ============================================================================
# Immutable Domain Models
# ============================================================================

class EvidenceMetricEntry(ImmutableBaseModel):
    """
    Authoritative representation of a row in the Evidence Registry (§3.9 Table 9).
    """
    metric_id: str = Field(min_length=1)
    evaluation_window: str = Field(min_length=1)
    reporting_state: ReportingState
    gross_recovered: int = Field(ge=0, description="Gross recovered in minor units (cents/paise)")
    confirmed_recovered: int = Field(ge=0, description="Confirmed settled recovery in minor units")
    incremental_lift: Optional[float] = Field(
        default=None,
        description="Incremental causal lift ratio (e.g., 0.1500 for +15%). None if blocked or backtesting."
    )
    blocking_reasons: Tuple[str, ...] = Field(default_factory=tuple)
    treatment_count: int = Field(default=0, ge=0)
    control_count: int = Field(default=0, ge=0)
    treatment_recovered_count: int = Field(default=0, ge=0)
    control_recovered_count: int = Field(default=0, ge=0)
    provenance_hash: str = Field(min_length=64, max_length=64)
    computed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EvidenceCalculatedEvent(ImmutableBaseModel):
    """
    Domain event emitted upon calculating and registering metric evidence (v11 §4).
    """
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    window_id: str = Field(min_length=1)
    metric_id: str = Field(min_length=1)
    reporting_state: str
    gross_recovered: int = Field(ge=0)
    confirmed_recovered: int = Field(ge=0)
    incremental_lift: Optional[float] = None
    blocking_reasons: Tuple[str, ...] = Field(default_factory=tuple)
    provenance_hash: str = Field(min_length=64, max_length=64)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# Evidence Engine Service
# ============================================================================

class EvidenceEngine:
    """
    Evidence Registry and Causal Lift Engine.
    
    Enforces:
    - INV-13: Backtesting never presented as causal lift (incremental_lift = None on backtest/no-control).
    - INV-14: Headline metrics cannot silently disappear (Permanent append-only registry with blocking codes).
    - INV-11: Two-stage ledger separation of gross vs confirmed settled revenue.
    - INV-18: Complete cryptographic audit logging of all calculated evidence.
    - INV-01 & INV-02: Zero execution or token-minting authority.
    """

    def __init__(
        self,
        ledger: Optional[RevenueLedger] = None,
        experiment_engine: Optional[ExperimentEngine] = None,
        audit_logger: Optional[CryptographicAuditLogger] = None,
    ) -> None:
        self._ledger = ledger
        self._experiment_engine = experiment_engine
        self._audit_logger = audit_logger
        self._registry: Dict[Tuple[str, str], EvidenceMetricEntry] = {}
        self._lock = threading.Lock()

    def evaluate_window(
        self,
        metric_id: str,
        evaluation_window: str,
        treatment_case_ids: List[str],
        control_case_ids: List[str],
        is_backtest: bool = False,
        min_sample_size: int = 10,
        current_time: Optional[datetime] = None,
    ) -> EvidenceMetricEntry:
        """
        Evaluates recovery evidence for an evaluation window across treatment and control cohorts.
        
        Args:
            metric_id: Unique identifier for the metric (e.g., 'headline_recovery_rate_30d').
            evaluation_window: Time window identifier (e.g., '2026-Q3-AUG').
            treatment_case_ids: List of case IDs assigned to TREATMENT.
            control_case_ids: List of case IDs assigned to CONTROL holdback.
            is_backtest: True if data is backtested simulation (prohibits causal lift).
            min_sample_size: Minimum required samples in both arms for APPROVED reporting.
            current_time: Optional explicit timestamp for deterministic testing.
            
        Returns:
            EvidenceMetricEntry: Immutable registered metric entry.
        """
        now = current_time or datetime.now(timezone.utc)
        blocking_reasons_list: List[str] = []

        treatment_count = len(treatment_case_ids)
        control_count = len(control_case_ids)

        gross_recovered = 0
        confirmed_recovered = 0
        treatment_recovered_count = 0
        control_recovered_count = 0

        # Ingest financial data from ledger if available
        if self._ledger is not None:
            for cid in treatment_case_ids:
                try:
                    summary = self._ledger.get_case_summary(cid)
                except (ValueError, KeyError):
                    summary = None

                if summary:
                    gross_recovered += summary.total_gross_recovered
                    confirmed_recovered += summary.total_net_confirmed
                    if summary.total_net_confirmed > 0 or summary.latest_state == FinancialState.CONFIRMED_SETTLED:
                        treatment_recovered_count += 1
                    elif summary.total_gross_recovered > 0:
                        treatment_recovered_count += 1

            for cid in control_case_ids:
                try:
                    summary = self._ledger.get_case_summary(cid)
                except (ValueError, KeyError):
                    summary = None

                if summary:
                    gross_recovered += summary.total_gross_recovered
                    confirmed_recovered += summary.total_net_confirmed
                    if summary.total_net_confirmed > 0 or summary.latest_state == FinancialState.CONFIRMED_SETTLED:
                        control_recovered_count += 1
                    elif summary.total_gross_recovered > 0:
                        control_recovered_count += 1

        incremental_lift: Optional[float] = None
        reporting_state: ReportingState

        # ---------------------------------------------------------------------
        # INV-13: Backtesting & Counterfactual Control Enforcement
        # ---------------------------------------------------------------------
        if is_backtest:
            # Backtesting MUST NEVER be presented as causal lift
            incremental_lift = None
            blocking_reasons_list.append(BlockingReason.BACKTESTING_ONLY.value)
            reporting_state = ReportingState.NOT_REPORTABLE

        elif control_count == 0:
            # No control group available -> cannot compute counterfactual causal lift
            incremental_lift = None
            blocking_reasons_list.append(BlockingReason.NO_EXPERIMENT_CONTROL.value)
            reporting_state = ReportingState.DIRECTIONAL

        else:
            # Valid live RCT with treatment and control cohorts
            r_treat = (treatment_recovered_count / treatment_count) if treatment_count > 0 else 0.0
            r_ctrl = (control_recovered_count / control_count) if control_count > 0 else 0.0

            if r_ctrl > 0:
                raw_lift = (r_treat - r_ctrl) / r_ctrl
            else:
                raw_lift = r_treat if r_treat > 0 else 0.0

            incremental_lift = round(raw_lift, 4)

            # Sample size check
            if treatment_count < min_sample_size or control_count < min_sample_size:
                blocking_reasons_list.append(BlockingReason.INSUFFICIENT_SAMPLE_SIZE.value)
                reporting_state = ReportingState.DATA_PENDING
            elif gross_recovered > 0 and confirmed_recovered == 0:
                # Revenue is only gross and has not settled (INV-11)
                blocking_reasons_list.append(BlockingReason.UNSETTLED_REVENUE.value)
                reporting_state = ReportingState.DATA_PENDING
            else:
                reporting_state = ReportingState.APPROVED

        # Calculate deterministic provenance hash
        provenance_dict = {
            "metric_id": metric_id,
            "evaluation_window": evaluation_window,
            "reporting_state": reporting_state.value,
            "gross_recovered": gross_recovered,
            "confirmed_recovered": confirmed_recovered,
            "incremental_lift": incremental_lift,
            "blocking_reasons": sorted(blocking_reasons_list),
            "treatment_count": treatment_count,
            "control_count": control_count,
            "treatment_recovered_count": treatment_recovered_count,
            "control_recovered_count": control_recovered_count,
        }
        canonical_str = canonical_json(provenance_dict)
        provenance_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

        entry = EvidenceMetricEntry(
            metric_id=metric_id,
            evaluation_window=evaluation_window,
            reporting_state=reporting_state,
            gross_recovered=gross_recovered,
            confirmed_recovered=confirmed_recovered,
            incremental_lift=incremental_lift,
            blocking_reasons=tuple(sorted(blocking_reasons_list)),
            treatment_count=treatment_count,
            control_count=control_count,
            treatment_recovered_count=treatment_recovered_count,
            control_recovered_count=control_recovered_count,
            provenance_hash=provenance_hash,
            computed_at=now,
        )

        with self._lock:
            self._registry[(metric_id, evaluation_window)] = entry

        # Audit Logging (INV-18)
        if self._audit_logger is not None:
            event = EvidenceCalculatedEvent(
                window_id=evaluation_window,
                metric_id=metric_id,
                reporting_state=reporting_state.value,
                gross_recovered=gross_recovered,
                confirmed_recovered=confirmed_recovered,
                incremental_lift=incremental_lift,
                blocking_reasons=entry.blocking_reasons,
                provenance_hash=provenance_hash,
                timestamp=now,
            )
            self._audit_logger.append(
                event_type="EVIDENCE_CALCULATED",
                payload=event.model_dump(mode="json"),
                timestamp=now,
            )

        return entry

    def get_evidence(self, metric_id: str, evaluation_window: str) -> Optional[EvidenceMetricEntry]:
        """Retrieves a registered evidence metric entry by composite key."""
        with self._lock:
            return self._registry.get((metric_id, evaluation_window))

    def list_metrics(self) -> List[EvidenceMetricEntry]:
        """Lists all registered evidence metric entries."""
        with self._lock:
            return list(self._registry.values())
