"""Comprehensive Unit and Safety Tests for Compliance Scheduler (TICKET-20).

Authoritative Basis:
- Frozen Architecture Baseline v11 Requirements.
- INV-01: AI recommends; it does not execute.
- INV-02: Least-privilege authority boundaries.
- INV-07: Mandatory compliance obligations cannot be discarded.
- INV-08: Multi-way obligation collision resolution with legal safety fallbacks.
- INV-09: Safety freezes cannot be bypassed via retries.
- INV-10: Incident obligations route through authoritative Scheduler.
- INV-18: Complete audit logging of compliance scheduling transitions.

Enforces:
1. Deterministic scheduling across all 4 ObligationTypes.
2. Mandatory obligation preservation and non-discarding guarantees.
3. Multi-way collision resolution and deterministic type precedence.
4. Incident-generated obligation ingestion into common queue.
5. Frozen case safety handling (non-mandatory frozen, mandatory preserved).
6. Immutability of obligation models and plans.
7. Append-only audit logging and hash-chain verification.
8. 100-repetition mathematical determinism.
"""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from src.revenue_recovery.foundation.audit import CryptographicAuditLogger
from src.revenue_recovery.foundation.events import (
    CaseState,
    ComplianceObligation,
    ObligationType,
    RecoveryCase,
    RiskTier,
)
from src.revenue_recovery.governance import (
    ComplianceScheduler,
    ObligationScheduledEvent,
    ObligationStatus,
    ScheduledObligationPlan,
)


@pytest.fixture
def audit_logger() -> CryptographicAuditLogger:
    return CryptographicAuditLogger()


@pytest.fixture
def standard_case() -> RecoveryCase:
    return RecoveryCase(
        customer_id="cust_sched_001",
        trigger_event_id="evt_sched_001",
        amount_in_cents=25000,
        currency="INR",
        state=CaseState.DIAGNOSED,
        risk_tier=RiskTier.LOW,
        attempt_count=0,
        max_attempts=3,
    )


@pytest.fixture
def frozen_case() -> RecoveryCase:
    return RecoveryCase(
        customer_id="cust_frozen_001",
        trigger_event_id="evt_frozen_001",
        amount_in_cents=50000,
        currency="INR",
        state=CaseState.FROZEN,
        risk_tier=RiskTier.HIGH,
        attempt_count=1,
        max_attempts=3,
    )


# ============================================================================
# PART 1: Core Scheduling & All 4 Obligation Types
# ============================================================================

class TestCoreSchedulingAndObligationTypes:
    """Verifies that all 4 obligation types can be scheduled and retrieved deterministically."""

    @pytest.mark.parametrize(
        "ob_type",
        [
            ObligationType.MANDATORY_DISCLOSURE,
            ObligationType.CONSENT_CHECK,
            ObligationType.COOLING_OFF,
            ObligationType.RETRY_WINDOW,
        ],
    )
    def test_scheduling_individual_obligation_types(
        self,
        ob_type: ObligationType,
        standard_case: RecoveryCase,
    ):
        scheduler = ComplianceScheduler()
        t0 = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
        ob = ComplianceObligation(
            case_id=standard_case.case_id,
            obligation_type=ob_type,
            is_mandatory=True,
            scheduled_time=t0,
        )

        scheduled = scheduler.schedule_obligation(ob)
        assert scheduled.obligation_id == ob.obligation_id
        assert scheduled.status == ObligationStatus.PENDING.value

        pending = scheduler.get_pending_obligations(case_id=standard_case.case_id)
        assert len(pending) == 1
        assert pending[0].obligation_id == ob.obligation_id

    def test_schedule_case_obligations_batch(self, standard_case: RecoveryCase):
        scheduler = ComplianceScheduler()
        t1 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 9, 1, 11, 0, 0, tzinfo=timezone.utc)

        ob1 = ComplianceObligation(
            case_id=standard_case.case_id,
            obligation_type=ObligationType.MANDATORY_DISCLOSURE,
            is_mandatory=True,
            scheduled_time=t1,
        )
        ob2 = ComplianceObligation(
            case_id=standard_case.case_id,
            obligation_type=ObligationType.RETRY_WINDOW,
            is_mandatory=False,
            scheduled_time=t2,
        )

        plan = scheduler.schedule_case_obligations(case=standard_case, obligations=[ob1, ob2])
        assert plan.case_id == standard_case.case_id
        assert len(plan.scheduled_obligations) == 2
        assert len(plan.collision_resolutions) == 0

    def test_mismatched_case_id_raises_value_error(self, standard_case: RecoveryCase):
        scheduler = ComplianceScheduler()
        foreign_ob = ComplianceObligation(
            case_id="case_foreign_999",
            obligation_type=ObligationType.MANDATORY_DISCLOSURE,
            is_mandatory=True,
            scheduled_time=datetime.now(timezone.utc),
        )
        with pytest.raises(ValueError, match="Mismatched case_id"):
            scheduler.schedule_case_obligations(case=standard_case, obligations=[foreign_ob])


# ============================================================================
# PART 2: Multi-Way Collision Resolution & Precedence (INV-07, INV-08)
# ============================================================================

class TestMultiWayCollisionResolution:
    """Verifies deterministic precedence arbitration and mandatory preservation."""

    def test_mandatory_overrides_optional_at_same_timestamp(self, standard_case: RecoveryCase):
        scheduler = ComplianceScheduler()
        t_collide = datetime(2026, 9, 1, 14, 0, 0, tzinfo=timezone.utc)

        optional_ob = ComplianceObligation(
            obligation_id="ob_opt_retry",
            case_id=standard_case.case_id,
            obligation_type=ObligationType.RETRY_WINDOW,
            is_mandatory=False,
            scheduled_time=t_collide,
        )
        mandatory_ob = ComplianceObligation(
            obligation_id="ob_mand_disclosure",
            case_id=standard_case.case_id,
            obligation_type=ObligationType.MANDATORY_DISCLOSURE,
            is_mandatory=True,
            scheduled_time=t_collide,
        )

        plan = scheduler.schedule_case_obligations(
            case=standard_case,
            obligations=[optional_ob, mandatory_ob],
        )

        # Dominant: mandatory disclosure remains scheduled and PENDING
        assert len(plan.scheduled_obligations) == 1
        assert plan.scheduled_obligations[0].obligation_id == "ob_mand_disclosure"
        assert plan.scheduled_obligations[0].status == ObligationStatus.PENDING.value

        # Subordinate: optional retry is marked COLLISION_RESOLVED with reason
        assert len(plan.collision_resolutions) == 1
        resolved = plan.collision_resolutions[0]
        assert resolved.obligation_id == "ob_opt_retry"
        assert resolved.status == ObligationStatus.COLLISION_RESOLVED.value
        assert "subordinate to MANDATORY_DISCLOSURE" in (resolved.resolution_reason or "")

    def test_four_way_type_precedence_hierarchy(self, standard_case: RecoveryCase):
        scheduler = ComplianceScheduler()
        t_same = datetime(2026, 9, 1, 15, 0, 0, tzinfo=timezone.utc)

        # Create all 4 types at the exact same timestamp with is_mandatory=True
        ob_retry = ComplianceObligation(
            obligation_id="ob_4_retry",
            case_id=standard_case.case_id,
            obligation_type=ObligationType.RETRY_WINDOW,
            is_mandatory=True,
            scheduled_time=t_same,
        )
        ob_cooling = ComplianceObligation(
            obligation_id="ob_3_cooling",
            case_id=standard_case.case_id,
            obligation_type=ObligationType.COOLING_OFF,
            is_mandatory=True,
            scheduled_time=t_same,
        )
        ob_consent = ComplianceObligation(
            obligation_id="ob_2_consent",
            case_id=standard_case.case_id,
            obligation_type=ObligationType.CONSENT_CHECK,
            is_mandatory=True,
            scheduled_time=t_same,
        )
        ob_disclosure = ComplianceObligation(
            obligation_id="ob_1_disclosure",
            case_id=standard_case.case_id,
            obligation_type=ObligationType.MANDATORY_DISCLOSURE,
            is_mandatory=True,
            scheduled_time=t_same,
        )

        plan = scheduler.schedule_case_obligations(
            case=standard_case,
            obligations=[ob_retry, ob_cooling, ob_consent, ob_disclosure],
        )

        # MANDATORY_DISCLOSURE is Rank 1 -> Must be dominant
        assert len(plan.scheduled_obligations) == 1
        assert plan.scheduled_obligations[0].obligation_id == "ob_1_disclosure"

        # The other 3 must be in collision_resolutions
        assert len(plan.collision_resolutions) == 3
        res_ids = [r.obligation_id for r in plan.collision_resolutions]
        assert "ob_2_consent" in res_ids
        assert "ob_3_cooling" in res_ids
        assert "ob_4_retry" in res_ids

    def test_deterministic_tie_breaking_for_same_type_collisions(self, standard_case: RecoveryCase):
        scheduler = ComplianceScheduler()
        t_same = datetime(2026, 9, 1, 16, 0, 0, tzinfo=timezone.utc)

        # Two mandatory disclosures at same time -> tie-breaker is obligation_id lexicographical
        ob_z = ComplianceObligation(
            obligation_id="ob_z_disclosure",
            case_id=standard_case.case_id,
            obligation_type=ObligationType.MANDATORY_DISCLOSURE,
            is_mandatory=True,
            scheduled_time=t_same,
        )
        ob_a = ComplianceObligation(
            obligation_id="ob_a_disclosure",
            case_id=standard_case.case_id,
            obligation_type=ObligationType.MANDATORY_DISCLOSURE,
            is_mandatory=True,
            scheduled_time=t_same,
        )

        plan = scheduler.schedule_case_obligations(case=standard_case, obligations=[ob_z, ob_a])
        assert plan.scheduled_obligations[0].obligation_id == "ob_a_disclosure"
        assert plan.collision_resolutions[0].obligation_id == "ob_z_disclosure"


# ============================================================================
# PART 3: Incident Ingestion & Frozen Case Safety (INV-09, INV-10)
# ============================================================================

class TestIncidentIngestionAndFrozenSafety:
    """Verifies common queue ingestion for incidents and safety freeze protection."""

    def test_incident_generated_obligation_ingestion(self, standard_case: RecoveryCase):
        scheduler = ComplianceScheduler()
        t_inc = datetime(2026, 9, 1, 17, 0, 0, tzinfo=timezone.utc)

        incident_ob = ComplianceObligation(
            obligation_id="ob_incident_outage_disclosure",
            case_id=standard_case.case_id,
            obligation_type=ObligationType.MANDATORY_DISCLOSURE,
            is_mandatory=True,
            scheduled_time=t_inc,
            resolution_reason="Incident: Payment Gateway Outage Notice",
        )

        # Ingested via standard scheduler path (INV-10)
        scheduled = scheduler.schedule_obligation(incident_ob)
        assert scheduled.obligation_id == incident_ob.obligation_id
        assert scheduled.status == ObligationStatus.PENDING.value

        pending = scheduler.get_pending_obligations(case_id=standard_case.case_id)
        assert any(o.obligation_id == "ob_incident_outage_disclosure" for o in pending)

    def test_frozen_case_freezes_optional_and_preserves_mandatory(self, frozen_case: RecoveryCase):
        scheduler = ComplianceScheduler()
        t0 = datetime(2026, 9, 1, 18, 0, 0, tzinfo=timezone.utc)

        mand_ob = ComplianceObligation(
            obligation_id="ob_mand_fz",
            case_id=frozen_case.case_id,
            obligation_type=ObligationType.MANDATORY_DISCLOSURE,
            is_mandatory=True,
            scheduled_time=t0,
        )
        opt_ob = ComplianceObligation(
            obligation_id="ob_opt_fz",
            case_id=frozen_case.case_id,
            obligation_type=ObligationType.RETRY_WINDOW,
            is_mandatory=False,
            scheduled_time=t0,
        )

        plan = scheduler.schedule_case_obligations(
            case=frozen_case,
            obligations=[mand_ob, opt_ob],
        )

        # Mandatory obligation remains protected and PENDING (INV-07)
        pending = scheduler.get_pending_obligations(case_id=frozen_case.case_id)
        assert len(pending) == 1
        assert pending[0].obligation_id == "ob_mand_fz"
        assert pending[0].status == ObligationStatus.PENDING.value

        # Non-mandatory obligation transitioned to FROZEN (INV-09)
        all_case_obs = scheduler._store[frozen_case.case_id]
        opt_in_store = next(o for o in all_case_obs if o.obligation_id == "ob_opt_fz")
        assert opt_in_store.status == ObligationStatus.FROZEN.value


# ============================================================================
# PART 4: Immutability, Audit Trail & Determinism (INV-18)
# ============================================================================

class TestSchedulerImmutabilityAuditAndDeterminism:
    """Verifies immutable replacement, audit event generation, and determinism."""

    def test_immutability_of_plan_and_obligations(self, standard_case: RecoveryCase):
        scheduler = ComplianceScheduler()
        t0 = datetime(2026, 9, 1, 19, 0, 0, tzinfo=timezone.utc)
        ob = ComplianceObligation(
            case_id=standard_case.case_id,
            obligation_type=ObligationType.MANDATORY_DISCLOSURE,
            is_mandatory=True,
            scheduled_time=t0,
        )
        plan = scheduler.schedule_case_obligations(case=standard_case, obligations=[ob])

        with pytest.raises((ValidationError, TypeError)):
            ob.status = ObligationStatus.SATISFIED.value  # type: ignore

        with pytest.raises((ValidationError, TypeError)):
            plan.case_id = "mutated_case_id"  # type: ignore

    def test_audit_logger_records_obligation_scheduled_events(
        self,
        standard_case: RecoveryCase,
        audit_logger: CryptographicAuditLogger,
    ):
        t0 = datetime(2026, 9, 1, 20, 0, 0, tzinfo=timezone.utc)
        scheduler = ComplianceScheduler(audit_logger=audit_logger)

        ob = ComplianceObligation(
            case_id=standard_case.case_id,
            obligation_type=ObligationType.MANDATORY_DISCLOSURE,
            is_mandatory=True,
            scheduled_time=t0,
        )
        scheduler.schedule_case_obligations(case=standard_case, obligations=[ob], current_time=t0)

        assert len(audit_logger.entries) >= 1
        entry = audit_logger.entries[0]
        assert entry.event_type == "OBLIGATION_SCHEDULED"
        assert entry.payload["case_id"] == standard_case.case_id
        assert entry.payload["obligation_id"] == ob.obligation_id
        assert entry.payload["obligation_type"] == ObligationType.MANDATORY_DISCLOSURE.value
        assert entry.timestamp == t0

        # Verify cryptographic audit chain integrity
        assert audit_logger.verify_chain_integrity() is True

    def test_100_repetition_determinism(self, standard_case: RecoveryCase):
        t_collide = datetime(2026, 9, 1, 21, 0, 0, tzinfo=timezone.utc)
        ob1 = ComplianceObligation(
            obligation_id="ob_rep_1",
            case_id=standard_case.case_id,
            obligation_type=ObligationType.RETRY_WINDOW,
            is_mandatory=False,
            scheduled_time=t_collide,
        )
        ob2 = ComplianceObligation(
            obligation_id="ob_rep_2",
            case_id=standard_case.case_id,
            obligation_type=ObligationType.MANDATORY_DISCLOSURE,
            is_mandatory=True,
            scheduled_time=t_collide,
        )

        plans = []
        for _ in range(100):
            sched = ComplianceScheduler()
            p = sched.schedule_case_obligations(standard_case, [ob1, ob2], current_time=t_collide)
            plans.append(p)

        first = plans[0]
        for p in plans:
            assert p.scheduled_obligations == first.scheduled_obligations
            assert p.collision_resolutions == first.collision_resolutions


# ============================================================================
# PART 5: Authority & Capability Boundaries (INV-01, INV-02)
# ============================================================================

class TestComplianceSchedulerAuthorityBoundaries:
    """Verifies that ComplianceScheduler has zero execution or authorization authority."""

    def test_scheduler_has_no_execution_or_minting_methods(self):
        scheduler = ComplianceScheduler()
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
            assert not hasattr(scheduler, method_name), f"ComplianceScheduler must NOT have method '{method_name}'"
