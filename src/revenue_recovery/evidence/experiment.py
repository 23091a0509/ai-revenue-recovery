"""Randomized Controlled Experiment Stratification and Assignment Engine (TICKET-26).

Authoritative Basis:
- Frozen Architecture Baseline v11 Requirements.
- INV-01: AI recommends; it does not execute.
- INV-02: Least-privilege authority boundaries (Evidence/Experiment engine with zero execution/token-minting authority).
- INV-13: Backtesting never presented as causal lift (Requires randomized controlled experiment logs for counterfactual baseline).
- INV-18: Complete audit logging of all assignments via append-only cryptographic logger.
"""

from datetime import datetime, timezone
import hashlib
import threading
from typing import Dict, Optional
import uuid

from pydantic import Field, field_validator, model_validator

from src.revenue_recovery.foundation.audit import CryptographicAuditLogger
from src.revenue_recovery.foundation.events import (
    ImmutableBaseModel,
    RecoveryCase,
    RiskTier,
)
from src.revenue_recovery.governance.arbitrator import ExperimentAssignment


# ============================================================================
# Immutable Experiment Domain Models (v11 Baseline §3.5, §3.9)
# ============================================================================

class StratumKey(ImmutableBaseModel):
    """Stratification key for partition isolation."""
    risk_tier: RiskTier
    currency: str
    failure_code: Optional[str] = None

    def to_canonical_str(self) -> str:
        """Produces canonical deterministic stratum string."""
        tier_str = self.risk_tier.value if isinstance(self.risk_tier, RiskTier) else str(self.risk_tier)
        curr_str = self.currency.strip().upper()
        fail_str = (self.failure_code or "NONE").strip().upper()
        return f"{tier_str}:{curr_str}:{fail_str}"


class ExperimentConfig(ImmutableBaseModel):
    """
    Configuration for an A/B or multi-arm randomized controlled experiment.
    Enforces strict ratio bounds summing to 1.0.
    """
    experiment_id: str = Field(..., min_length=1, max_length=64)
    name: str = Field(..., min_length=1, max_length=128)
    treatment_ratio: float = Field(default=0.80, ge=0.0, le=1.0)
    control_ratio: float = Field(default=0.10, ge=0.0, le=1.0)
    excluded_ratio: float = Field(default=0.10, ge=0.0, le=1.0)
    salt: str = Field(default="exp_salt_v1", min_length=1, max_length=64)
    is_active: bool = Field(default=True)

    @model_validator(mode="after")
    def validate_ratios_sum_to_one(self) -> "ExperimentConfig":
        total = self.treatment_ratio + self.control_ratio + self.excluded_ratio
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                f"ExperimentConfig ratios must sum to 1.0 (within tolerance), got total={total:.6f} "
                f"(treatment={self.treatment_ratio}, control={self.control_ratio}, excluded={self.excluded_ratio})"
            )
        return self


class ExperimentAssignmentRecord(ImmutableBaseModel):
    """Immutable record of an experiment assignment."""
    assignment_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    experiment_id: str
    case_id: str
    customer_id: str
    stratum: str
    assignment: ExperimentAssignment
    bucket_score: float = Field(..., ge=0.0, le=1.0)
    assigned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ExperimentAssignedEvent(ImmutableBaseModel):
    """Domain event emitted when a case is assigned to an experiment arm."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    customer_id: str
    experiment_id: str
    assignment: ExperimentAssignment
    stratum: str
    bucket_score: float
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# Authoritative Experiment Engine Service (TICKET-26)
# ============================================================================

class ExperimentEngine:
    """
    Randomized Controlled Experiment Stratification and Assignment Engine.
    Enforces deterministic SHA-256 stratified hashing into TREATMENT, CONTROL, or EXCLUDED arms.
    Authority Boundaries:
    - Zero execution authority (INV-01)
    - Zero token-minting authority (INV-02)
    - Strict append-only audit trail (INV-18)
    - Scientific counterfactual logs for causal lift (INV-13)
    """

    def __init__(
        self,
        default_config: Optional[ExperimentConfig] = None,
        audit_logger: Optional[CryptographicAuditLogger] = None,
    ) -> None:
        self.audit_logger = audit_logger
        self._lock = threading.Lock()
        self._experiments: Dict[str, ExperimentConfig] = {}
        self._assignments: Dict[str, Dict[str, ExperimentAssignmentRecord]] = {}

        if default_config is not None:
            self.register_experiment(default_config)
            self._default_experiment_id = default_config.experiment_id
        else:
            # Default fallback experiment: 80% TREATMENT, 10% CONTROL, 10% EXCLUDED
            default_exp = ExperimentConfig(
                experiment_id="default_recovery_rct",
                name="Default Recovery RCT 80/10/10",
                treatment_ratio=0.80,
                control_ratio=0.10,
                excluded_ratio=0.10,
                salt="default_rct_salt_v1",
                is_active=True,
            )
            self.register_experiment(default_exp)
            self._default_experiment_id = default_exp.experiment_id

    def register_experiment(self, config: ExperimentConfig) -> None:
        """Registers or updates an experiment configuration in a thread-safe manner."""
        with self._lock:
            self._experiments[config.experiment_id] = config

    def get_experiment(self, experiment_id: str) -> ExperimentConfig:
        """Retrieves experiment configuration by ID."""
        with self._lock:
            if experiment_id not in self._experiments:
                raise KeyError(f"Experiment '{experiment_id}' is not registered.")
            return self._experiments[experiment_id]

    def compute_stratum(self, case: RecoveryCase, failure_code: Optional[str] = None) -> str:
        """Derives the canonical stratum string from case attributes."""
        tier = case.risk_tier
        curr = case.currency
        return StratumKey(risk_tier=tier, currency=curr, failure_code=failure_code).to_canonical_str()

    def compute_bucket_score(self, salt: str, experiment_id: str, customer_id: str, stratum: str) -> float:
        """
        Computes deterministic bucket score in [0.0, 1.0) using SHA-256.
        Formula:
            unit_key = f"{salt}:{experiment_id}:{customer_id}:{stratum}"
            hash = sha256(unit_key)
            score = int(hash[:16], 16) / 2^64
        """
        unit_key = f"{salt}:{experiment_id}:{customer_id}:{stratum}"
        digest = hashlib.sha256(unit_key.encode("utf-8")).hexdigest()
        val_64 = int(digest[:16], 16)
        # Normalize 64-bit integer to [0.0, 1.0)
        return val_64 / float(1 << 64)

    def assign(
        self,
        case: RecoveryCase,
        experiment_id: Optional[str] = None,
        stratum_override: Optional[str] = None,
        current_time: Optional[datetime] = None,
        failure_code: Optional[str] = None,
    ) -> ExperimentAssignmentRecord:
        """
        Deterministically assigns a recovery case to an experiment arm (TREATMENT, CONTROL, EXCLUDED)
        based on stratified hashing, records assignment, and emits audit event.
        """
        exp_id = experiment_id or self._default_experiment_id
        now = current_time or datetime.now(timezone.utc)

        with self._lock:
            if exp_id not in self._experiments:
                raise KeyError(f"Experiment '{exp_id}' is not registered.")
            config = self._experiments[exp_id]

            if not config.is_active:
                raise ValueError(f"Experiment '{exp_id}' is inactive and cannot accept assignments.")

            # Check if case was already assigned in this experiment (Idempotency)
            if case.case_id in self._assignments and exp_id in self._assignments[case.case_id]:
                return self._assignments[case.case_id][exp_id]

            stratum = stratum_override or self.compute_stratum(case, failure_code=failure_code)
            bucket_score = self.compute_bucket_score(
                salt=config.salt,
                experiment_id=config.experiment_id,
                customer_id=case.customer_id,
                stratum=stratum,
            )

            # Map bucket score to experiment arm
            if bucket_score < config.treatment_ratio:
                assignment = ExperimentAssignment.TREATMENT
            elif bucket_score < (config.treatment_ratio + config.control_ratio):
                assignment = ExperimentAssignment.CONTROL
            else:
                assignment = ExperimentAssignment.EXCLUDED

            record = ExperimentAssignmentRecord(
                assignment_id=str(uuid.uuid4()),
                experiment_id=config.experiment_id,
                case_id=case.case_id,
                customer_id=case.customer_id,
                stratum=stratum,
                assignment=assignment,
                bucket_score=bucket_score,
                assigned_at=now,
            )

            if case.case_id not in self._assignments:
                self._assignments[case.case_id] = {}
            self._assignments[case.case_id][exp_id] = record

            # Emit audit event if logger present
            self._record_assignment_audit_event(record, now)

            return record

    def get_assignment_for_case(
        self, case_id: str, experiment_id: Optional[str] = None
    ) -> Optional[ExperimentAssignmentRecord]:
        """Retrieves existing assignment for a case."""
        exp_id = experiment_id or self._default_experiment_id
        with self._lock:
            case_map = self._assignments.get(case_id)
            if case_map is None:
                return None
            return case_map.get(exp_id)

    def _record_assignment_audit_event(
        self, record: ExperimentAssignmentRecord, current_time: datetime
    ) -> None:
        """Records EXPERIMENT_ASSIGNED audit event into CryptographicAuditLogger."""
        if self.audit_logger is None:
            return

        payload = {
            "assignment_id": record.assignment_id,
            "experiment_id": record.experiment_id,
            "case_id": record.case_id,
            "customer_id": record.customer_id,
            "stratum": record.stratum,
            "assignment": record.assignment.value if isinstance(record.assignment, ExperimentAssignment) else str(record.assignment),
            "bucket_score": record.bucket_score,
            "assigned_at": record.assigned_at.isoformat(),
        }

        self.audit_logger.append(
            event_type="EXPERIMENT_ASSIGNED",
            payload=payload,
            timestamp=current_time,
        )
