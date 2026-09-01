"""Deterministic Compliance Scheduler with Multi-Way Collision Resolver (TICKET-20).

Architecture Baseline: Frozen Architecture Baseline v11.
Enforces:
- INV-01: AI recommends; it does not execute (Compliance Scheduler operates deterministically on obligations).
- INV-02: Least-privilege authority boundaries (Governance scheduling with zero execution authority).
- INV-07: Mandatory compliance obligations cannot be discarded (Preserves all mandatory disclosures).
- INV-08: Multi-way obligation collision resolution (Deterministic precedence arbitration).
- INV-09: Safety freezes cannot be bypassed (Freezes non-mandatory obligations upon case safety freeze).
- INV-10: Incident obligations route through authoritative Scheduler (Common ingestion queue).
- INV-18: Complete audit logging of obligation scheduling via append-only cryptographic logger.
"""

from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
import threading
from typing import Any, Optional, Sequence
import uuid
from pydantic import Field, field_validator

from src.revenue_recovery.foundation.audit import CryptographicAuditLogger
from src.revenue_recovery.foundation.events import (
    CaseState,
    ComplianceObligation,
    ImmutableBaseModel,
    ObligationType,
    RecoveryCase,
)


# ============================================================================
# Core Scheduler Enums
# ============================================================================

class ObligationStatus(str, Enum):
    """Authoritative lifecycle status for a ComplianceObligation (v11 Baseline §3.4)."""
    PENDING = "PENDING"
    SATISFIED = "SATISFIED"
    COLLISION_RESOLVED = "COLLISION_RESOLVED"
    EXPIRED = "EXPIRED"
    FROZEN = "FROZEN"


# ============================================================================
# Core Scheduler Domain Models
# ============================================================================

class ScheduledObligationPlan(ImmutableBaseModel):
    """Immutable record of scheduled compliance obligations and resolved collisions."""
    case_id: str = Field(min_length=1)
    scheduled_obligations: tuple[ComplianceObligation, ...] = Field(default_factory=tuple)
    collision_resolutions: tuple[ComplianceObligation, ...] = Field(default_factory=tuple)
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("scheduled_obligations", "collision_resolutions", mode="before")
    @classmethod
    def convert_to_tuples(cls, v: Any) -> tuple:
        if isinstance(v, tuple):
            return v
        if isinstance(v, (list, set)):
            return tuple(v)
        return v


class ObligationScheduledEvent(ImmutableBaseModel):
    """Domain event emitted upon scheduling or status change of a ComplianceObligation (v11 §4)."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    obligation_id: str
    obligation_type: str
    is_mandatory: bool
    scheduled_time: datetime
    status: str
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# Compliance Scheduler Service
# ============================================================================

class ComplianceScheduler:
    """
    Deterministic Compliance Scheduler with Multi-Way Collision Resolver.
    
    Architectural Boundaries (v11 Baseline):
    - Read Access: ComplianceObligations, Case context, Calendar.
    - Decision Role: Deterministic obligation scheduling & collision handling.
    - Authorize Role: None (Zero token minting capabilities).
    - Execute Role: None (Zero execution or provider calling capabilities).
    - Network Egress: None / Internal DB only.
    """

    def __init__(
        self,
        audit_logger: Optional[CryptographicAuditLogger] = None,
    ) -> None:
        # Internal thread-safe store: case_id -> list of ComplianceObligation
        self._store: dict[str, list[ComplianceObligation]] = defaultdict(list)
        self._lock = threading.RLock()
        self.audit_logger: Optional[CryptographicAuditLogger] = audit_logger

    def schedule_obligation(
        self,
        obligation: ComplianceObligation,
        current_time: Optional[datetime] = None,
    ) -> ComplianceObligation:
        """
        Ingests and registers an individual compliance or incident obligation (INV-10).
        Ensures immutable storage and audit trail emission.
        """
        now = current_time or datetime.now(timezone.utc)
        with self._lock:
            # Replace existing if obligation_id matches, otherwise append
            case_obs = self._store[obligation.case_id]
            idx = next((i for i, o in enumerate(case_obs) if o.obligation_id == obligation.obligation_id), None)
            if idx is not None:
                case_obs[idx] = obligation
            else:
                case_obs.append(obligation)

            self._record_audit_event(obligation, now)
            return obligation

    def schedule_case_obligations(
        self,
        case: RecoveryCase,
        obligations: Sequence[ComplianceObligation],
        current_time: Optional[datetime] = None,
    ) -> ScheduledObligationPlan:
        """
        Ingests a sequence of obligations for a RecoveryCase and applies multi-way collision resolution.
        If the case is FROZEN, non-mandatory obligations are frozen (INV-09).
        """
        now = current_time or datetime.now(timezone.utc)
        with self._lock:
            for ob in obligations:
                if ob.case_id != case.case_id:
                    raise ValueError(
                        f"Mismatched case_id on obligation '{ob.obligation_id}': "
                        f"expected '{case.case_id}', got '{ob.case_id}'"
                    )

            # Ingest all new obligations into internal store
            for ob in obligations:
                self.schedule_obligation(ob, current_time=now)

            # If case is FROZEN, freeze non-mandatory obligations
            if case.state == CaseState.FROZEN:
                self.freeze_case_obligations(case.case_id, current_time=now)

            # Resolve multi-way collisions deterministically
            return self.resolve_collisions(case.case_id, current_time=now)

    def get_pending_obligations(
        self,
        case_id: Optional[str] = None,
        as_of: Optional[datetime] = None,
    ) -> tuple[ComplianceObligation, ...]:
        """
        Queries all active PENDING obligations, optionally filtered by case_id and maturity timestamp.
        Returns a sorted, immutable tuple of ComplianceObligation instances.
        """
        with self._lock:
            results: list[ComplianceObligation] = []
            target_case_ids = [case_id] if case_id else list(self._store.keys())

            for cid in sorted(target_case_ids):
                for ob in self._store.get(cid, []):
                    if ob.status == ObligationStatus.PENDING.value:
                        if as_of is None or ob.scheduled_time <= as_of:
                            results.append(ob)

            # Sort deterministically by (scheduled_time, is_mandatory DESC, type_rank, obligation_id)
            results.sort(key=self._obligation_sort_key)
            return tuple(results)

    def resolve_collisions(
        self,
        case_id: str,
        current_time: Optional[datetime] = None,
    ) -> ScheduledObligationPlan:
        """
        Deterministically resolves multi-way collisions across all active obligations for a case.
        
        Collision Precedence Rules (v11 Baseline INV-07, INV-08):
        1. is_mandatory=True overrides is_mandatory=False.
        2. Type Precedence:
           MANDATORY_DISCLOSURE (Rank 1) -> CONSENT_CHECK (Rank 2) -> COOLING_OFF (Rank 3) -> RETRY_WINDOW (Rank 4).
        3. Lexicographical obligation_id as deterministic tie-breaker.
        4. Dominant obligation remains PENDING at the collision timestamp.
        5. Subordinate conflicting obligations are marked COLLISION_RESOLVED with explicit resolution_reason.
        """
        now = current_time or datetime.now(timezone.utc)
        with self._lock:
            case_obs = list(self._store.get(case_id, []))
            if not case_obs:
                return ScheduledObligationPlan(
                    case_id=case_id,
                    scheduled_obligations=(),
                    collision_resolutions=(),
                    evaluated_at=now,
                )

            # Group active obligations by scheduled_time
            time_groups: dict[datetime, list[ComplianceObligation]] = defaultdict(list)
            for ob in case_obs:
                if ob.status in {ObligationStatus.PENDING.value, ObligationStatus.COLLISION_RESOLVED.value}:
                    time_groups[ob.scheduled_time].append(ob)

            resolved_plan_scheduled: list[ComplianceObligation] = []
            resolved_plan_collisions: list[ComplianceObligation] = []
            updated_store: list[ComplianceObligation] = []

            # Process time groups in deterministic chronological order
            for sched_time in sorted(time_groups.keys()):
                group = time_groups[sched_time]
                if len(group) == 1:
                    # No collision at this timestamp
                    ob = group[0]
                    resolved_plan_scheduled.append(ob)
                    updated_store.append(ob)
                else:
                    # Multi-way collision detected at sched_time
                    sorted_group = sorted(group, key=self._obligation_sort_key)
                    dominant = sorted_group[0]

                    # Ensure dominant is PENDING (create immutable replacement if needed)
                    if dominant.status != ObligationStatus.PENDING.value:
                        dominant = ComplianceObligation(
                            obligation_id=dominant.obligation_id,
                            case_id=dominant.case_id,
                            obligation_type=dominant.obligation_type,
                            is_mandatory=dominant.is_mandatory,
                            scheduled_time=dominant.scheduled_time,
                            status=ObligationStatus.PENDING.value,
                            resolution_reason=None,
                            created_at=dominant.created_at,
                        )
                        self._record_audit_event(dominant, now)

                    resolved_plan_scheduled.append(dominant)
                    updated_store.append(dominant)

                    # Subordinate obligations transition to COLLISION_RESOLVED
                    for subordinate in sorted_group[1:]:
                        dom_type = (
                            dominant.obligation_type.value
                            if isinstance(dominant.obligation_type, ObligationType)
                            else str(dominant.obligation_type)
                        )
                        reason = (
                            f"Collision resolved: subordinate to {dom_type} "
                            f"({dominant.obligation_id}) at {sched_time.isoformat()}"
                        )
                        sub_resolved = ComplianceObligation(
                            obligation_id=subordinate.obligation_id,
                            case_id=subordinate.case_id,
                            obligation_type=subordinate.obligation_type,
                            is_mandatory=subordinate.is_mandatory,
                            scheduled_time=subordinate.scheduled_time,
                            status=ObligationStatus.COLLISION_RESOLVED.value,
                            resolution_reason=reason,
                            created_at=subordinate.created_at,
                        )
                        resolved_plan_collisions.append(sub_resolved)
                        updated_store.append(sub_resolved)
                        self._record_audit_event(sub_resolved, now)

            # Preserve any non-colliding non-pending obligations (e.g. SATISFIED, EXPIRED, FROZEN)
            for ob in case_obs:
                if ob.status not in {ObligationStatus.PENDING.value, ObligationStatus.COLLISION_RESOLVED.value}:
                    updated_store.append(ob)

            self._store[case_id] = updated_store

            # Sort return lists deterministically
            resolved_plan_scheduled.sort(key=self._obligation_sort_key)
            resolved_plan_collisions.sort(key=self._obligation_sort_key)

            return ScheduledObligationPlan(
                case_id=case_id,
                scheduled_obligations=tuple(resolved_plan_scheduled),
                collision_resolutions=tuple(resolved_plan_collisions),
                evaluated_at=now,
            )

    def freeze_case_obligations(
        self,
        case_id: str,
        current_time: Optional[datetime] = None,
    ) -> tuple[ComplianceObligation, ...]:
        """
        Freezes pending non-mandatory obligations when a RecoveryCase enters FROZEN state (INV-09).
        Mandatory compliance obligations (is_mandatory=True) remain protected and are NOT discarded (INV-07).
        """
        now = current_time or datetime.now(timezone.utc)
        with self._lock:
            case_obs = self._store.get(case_id, [])
            frozen_results: list[ComplianceObligation] = []
            updated_store: list[ComplianceObligation] = []

            for ob in case_obs:
                if ob.status == ObligationStatus.PENDING.value and not ob.is_mandatory:
                    frozen_ob = ComplianceObligation(
                        obligation_id=ob.obligation_id,
                        case_id=ob.case_id,
                        obligation_type=ob.obligation_type,
                        is_mandatory=ob.is_mandatory,
                        scheduled_time=ob.scheduled_time,
                        status=ObligationStatus.FROZEN.value,
                        resolution_reason="Safety freeze triggered on RecoveryCase.",
                        created_at=ob.created_at,
                    )
                    frozen_results.append(frozen_ob)
                    updated_store.append(frozen_ob)
                    self._record_audit_event(frozen_ob, now)
                else:
                    updated_store.append(ob)

            self._store[case_id] = updated_store
            return tuple(frozen_results)

    def _obligation_sort_key(self, ob: ComplianceObligation) -> tuple:
        """Deterministic sort key enforcing type hierarchy and mandatory precedence."""
        type_ranks = {
            ObligationType.MANDATORY_DISCLOSURE.value: 1,
            ObligationType.CONSENT_CHECK.value: 2,
            ObligationType.COOLING_OFF.value: 3,
            ObligationType.RETRY_WINDOW.value: 4,
        }
        ob_type_str = (
            ob.obligation_type.value
            if isinstance(ob.obligation_type, ObligationType)
            else str(ob.obligation_type)
        )
        type_rank = type_ranks.get(ob_type_str, 99)
        # Sort by:
        # 1. scheduled_time ASC
        # 2. is_mandatory DESC (0 for True, 1 for False)
        # 3. type_rank ASC (1 to 4)
        # 4. obligation_id ASC (lexicographical)
        return (
            ob.scheduled_time,
            0 if ob.is_mandatory else 1,
            type_rank,
            ob.obligation_id,
        )

    def _record_audit_event(self, obligation: ComplianceObligation, now: datetime) -> None:
        """Appends an ObligationScheduledEvent to the audit logger if present (INV-18)."""
        if self.audit_logger is not None:
            ob_type_str = (
                obligation.obligation_type.value
                if isinstance(obligation.obligation_type, ObligationType)
                else str(obligation.obligation_type)
            )
            event = ObligationScheduledEvent(
                case_id=obligation.case_id,
                obligation_id=obligation.obligation_id,
                obligation_type=ob_type_str,
                is_mandatory=obligation.is_mandatory,
                scheduled_time=obligation.scheduled_time,
                status=obligation.status,
                occurred_at=now,
            )
            self.audit_logger.append(
                event_type="OBLIGATION_SCHEDULED",
                payload=event.model_dump(mode="json"),
                timestamp=now,
            )
