"""Control-Plane Arbitrator coordinating Safety, Compliance, Experiment, and Capacity (TICKET-21).

Architecture Baseline: Frozen Architecture Baseline v11.
Enforces:
- INV-01: AI recommends; it does not execute (Arbitrator determines cross-loop outcome).
- INV-02: Least-privilege authority boundaries (Governance arbitration with zero execution authority).
- INV-09: Safety freezes cannot be bypassed via retry (FROZEN cases strictly blocked/held).
- INV-18: Complete audit logging of arbitration evaluations via append-only cryptographic logger.
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any, Mapping, Optional
import uuid
from pydantic import Field, field_validator

from src.revenue_recovery.ai_decision.artifacts import DecisionArtifact
from src.revenue_recovery.foundation.audit import (
    CryptographicAuditLogger,
    ImmutableDict,
    canonical_json,
)
from src.revenue_recovery.foundation.events import (
    ActionChannel,
    ActionType,
    CaseState,
    ComplianceObligation,
    ImmutableBaseModel,
    ObligationType,
    RecoveryCase,
    RiskTier,
)
from src.revenue_recovery.governance.policy_engine import (
    PolicyEngine,
    PolicyEvaluationResult,
)
from src.revenue_recovery.governance.scheduler import (
    ComplianceScheduler,
    ObligationStatus,
)
from src.revenue_recovery.recovery_engine.diagnosis import DiagnosisResult
from src.revenue_recovery.safety.circuit_breaker import (
    CapacityExceededError,
    CapacityGovernor,
    CircuitBrokenError,
    GranularCircuitBreakerRegistry,
)
from src.revenue_recovery.safety.kill_switch import (
    KillSwitchManager,
)


# ============================================================================
# Core Arbitration Enums (v11 Baseline §3.5)
# ============================================================================

class SafetyVerdict(str, Enum):
    """Safety evaluation outcome."""
    PASS = "PASS"
    CIRCUIT_BROKEN = "CIRCUIT_BROKEN"
    KILL_SWITCH_ACTIVE = "KILL_SWITCH_ACTIVE"
    CAPACITY_EXCEEDED = "CAPACITY_EXCEEDED"


class ComplianceVerdict(str, Enum):
    """Compliance and policy evaluation outcome."""
    APPROVED = "APPROVED"
    BLOCKED = "BLOCKED"
    DEFERRED = "DEFERRED"


class ExperimentAssignment(str, Enum):
    """A/B experiment assignment and stratification state."""
    TREATMENT = "TREATMENT"
    CONTROL = "CONTROL"
    EXCLUDED = "EXCLUDED"


class ArbitratedOutcome(str, Enum):
    """Final arbitrated control-plane outcome."""
    PROCEED = "PROCEED"
    BLOCK = "BLOCK"
    DEFER = "DEFER"
    HOLD = "HOLD"


# ============================================================================
# Canonical Hashing Helper
# ============================================================================

def compute_canonical_arbitration_hash(payload: Mapping[str, Any] | dict[str, Any]) -> str:
    """Computes a deterministic SHA-256 hash over canonical JSON representation."""
    serialized = canonical_json(payload)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


# ============================================================================
# Core Arbitration Domain Models
# ============================================================================

class ArbitrationRecord(ImmutableBaseModel):
    """Authoritative immutable record of a control-plane arbitration decision (v11 §3.5)."""
    arbitration_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str = Field(min_length=1)
    decision_artifact_id: str = Field(min_length=1)
    safety_verdict: SafetyVerdict
    compliance_verdict: ComplianceVerdict
    experiment_assignment: ExperimentAssignment
    arbitrated_outcome: ArbitratedOutcome
    arbitration_hash: str = Field(min_length=64, max_length=64)
    rationale: str = Field(min_length=1)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("arbitration_hash")
    @classmethod
    def validate_hash_format(cls, v: str) -> str:
        v_lower = v.lower()
        if len(v_lower) != 64 or not all(c in "0123456789abcdef" for c in v_lower):
            raise ValueError("arbitration_hash must be a valid 64-character lowercase hex string")
        return v_lower


class ArbitrationEvaluatedEvent(ImmutableBaseModel):
    """Domain event emitted upon completion of a control-plane arbitration evaluation (v11 §4)."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    arbitration_id: str
    verdict: str  # ArbitratedOutcome value
    experiment_state: str  # ExperimentAssignment value
    arbitration_hash: str
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# Control-Plane Arbitrator Service
# ============================================================================

class ControlPlaneArbitrator:
    """
    Deterministic Control-Plane Arbitrator.
    
    Coordinates:
    1. Safety State (KillSwitch, CircuitBreaker, CapacityGovernor, CaseState.FROZEN)
    2. Compliance State (PolicyEngine, ComplianceScheduler)
    3. Experiment Assignment (Treatment vs. Control Holdback vs. Excluded)
    4. Deterministic Cross-Loop Prioritization & Output
    
    Architectural Boundaries (v11 Baseline):
    - Read Access: Safety state, Capacity, Experiment state, Policy, Calendar.
    - Decision Role: Cross-loop arbitration & prioritization (Returns ArbitrationRecord).
    - Authorize Role: None (Zero token minting capabilities).
    - Execute Role: None (Zero execution or provider calling capabilities).
    - Network Egress: None / Internal DB only.
    """

    def __init__(
        self,
        policy_engine: Optional[PolicyEngine] = None,
        scheduler: Optional[ComplianceScheduler] = None,
        kill_switch: Optional[KillSwitchManager] = None,
        circuit_breakers: Optional[GranularCircuitBreakerRegistry] = None,
        capacity_governor: Optional[CapacityGovernor] = None,
        audit_logger: Optional[CryptographicAuditLogger] = None,
    ) -> None:
        self.policy_engine: PolicyEngine = policy_engine or PolicyEngine()
        self.scheduler: ComplianceScheduler = scheduler or ComplianceScheduler()
        self.kill_switch: KillSwitchManager = kill_switch or KillSwitchManager()
        self.circuit_breakers: GranularCircuitBreakerRegistry = (
            circuit_breakers or GranularCircuitBreakerRegistry()
        )
        self.capacity_governor: CapacityGovernor = capacity_governor or CapacityGovernor()
        self.audit_logger: Optional[CryptographicAuditLogger] = audit_logger

    def arbitrate(
        self,
        case: RecoveryCase,
        diagnosis: DiagnosisResult,
        decision: DecisionArtifact,
        experiment_assignment: ExperimentAssignment = ExperimentAssignment.TREATMENT,
        policy_id: Optional[str] = None,
        current_time: Optional[datetime] = None,
    ) -> ArbitrationRecord:
        """
        Coordinates Safety, Compliance, Experiment, and Capacity to produce a deterministic ArbitrationRecord.
        
        Arbitration Matrix Precedence (v11 Baseline):
        1. Safety Gate:
           - KILL_SWITCH_ACTIVE -> BLOCK
           - CIRCUIT_BROKEN -> HOLD
           - CAPACITY_EXCEEDED -> HOLD
        2. Compliance Gate:
           - BLOCKED -> BLOCK
           - DEFERRED -> DEFER
        3. Experiment Gate:
           - CONTROL -> HOLD
           - EXCLUDED -> BLOCK
        4. Final Pass:
           - (PASS + APPROVED + TREATMENT) -> PROCEED
        """
        now = current_time or datetime.now(timezone.utc)

        # --------------------------------------------------------------------
        # Step 1: Evaluate Safety Gates
        # --------------------------------------------------------------------
        safety_verdict, safety_reason = self._evaluate_safety(case, decision, now)

        # --------------------------------------------------------------------
        # Step 2: Evaluate Compliance & Policy Gates
        # --------------------------------------------------------------------
        compliance_verdict, compliance_reason = self._evaluate_compliance(
            case, diagnosis, decision, policy_id, now
        )

        # --------------------------------------------------------------------
        # Step 3: Resolve Cross-Loop Arbitrated Outcome (Arbitration Matrix)
        # --------------------------------------------------------------------
        exp_val = getattr(experiment_assignment, "value", str(experiment_assignment))

        if safety_verdict == SafetyVerdict.KILL_SWITCH_ACTIVE:
            arbitrated_outcome = ArbitratedOutcome.BLOCK
            rationale = f"Safety Block: {safety_reason}"
        elif safety_verdict in {SafetyVerdict.CIRCUIT_BROKEN, SafetyVerdict.CAPACITY_EXCEEDED}:
            arbitrated_outcome = ArbitratedOutcome.HOLD
            rationale = f"Safety Hold: {safety_reason}"
        elif compliance_verdict == ComplianceVerdict.BLOCKED:
            arbitrated_outcome = ArbitratedOutcome.BLOCK
            rationale = f"Compliance Block: {compliance_reason}"
        elif compliance_verdict == ComplianceVerdict.DEFERRED:
            arbitrated_outcome = ArbitratedOutcome.DEFER
            rationale = f"Compliance Defer: {compliance_reason}"
        elif exp_val == ExperimentAssignment.CONTROL.value:
            arbitrated_outcome = ArbitratedOutcome.HOLD
            rationale = "Experiment Holdback: Case assigned to CONTROL group counterfactual baseline."
        elif exp_val == ExperimentAssignment.EXCLUDED.value:
            arbitrated_outcome = ArbitratedOutcome.BLOCK
            rationale = "Experiment Exclusion: Case is EXCLUDED from automated recovery."
        else:
            # All gates passed: PASS + APPROVED + TREATMENT
            arbitrated_outcome = ArbitratedOutcome.PROCEED
            rationale = "All governance gates passed: Safety PASS, Compliance APPROVED, Experiment TREATMENT."

        # --------------------------------------------------------------------
        # Step 4: Compute Canonical Arbitration Hash
        # --------------------------------------------------------------------
        canonical_payload = {
            "case_id": case.case_id,
            "decision_artifact_id": decision.artifact_id,
            "safety_verdict": getattr(safety_verdict, "value", str(safety_verdict)),
            "compliance_verdict": getattr(compliance_verdict, "value", str(compliance_verdict)),
            "experiment_assignment": exp_val,
            "arbitrated_outcome": getattr(arbitrated_outcome, "value", str(arbitrated_outcome)),
            "canonical_input_hash": decision.canonical_input_hash,
            "recommended_action": getattr(decision.recommended_action, "value", str(decision.recommended_action)),
        }
        arbitration_hash = compute_canonical_arbitration_hash(canonical_payload)

        record = ArbitrationRecord(
            case_id=case.case_id,
            decision_artifact_id=decision.artifact_id,
            safety_verdict=safety_verdict,
            compliance_verdict=compliance_verdict,
            experiment_assignment=experiment_assignment,
            arbitrated_outcome=arbitrated_outcome,
            arbitration_hash=arbitration_hash,
            rationale=rationale,
            created_at=now,
        )

        # --------------------------------------------------------------------
        # Step 5: Audit Event Emission (INV-18)
        # --------------------------------------------------------------------
        self._record_audit_event(record, now)

        return record

    def _evaluate_safety(
        self,
        case: RecoveryCase,
        decision: DecisionArtifact,
        now: datetime,
    ) -> tuple[SafetyVerdict, str]:
        """Evaluates Kill Switch, Circuit Breaker, Capacity, and Case Safety Freeze (INV-09, INV-15)."""
        action_val = getattr(decision.recommended_action, "value", str(decision.recommended_action))
        channel_val = decision.parameters.get("channel")

        # 1. Safety Freeze Guard (INV-09)
        if case.state == CaseState.FROZEN:
            return (
                SafetyVerdict.KILL_SWITCH_ACTIVE,
                f"Case '{case.case_id}' is in FROZEN state. Safety freeze blocks recovery.",
            )

        # 2. Kill Switch Gate
        if self.kill_switch.is_active(
            action_type=action_val,
            channel=channel_val,
            customer_id=case.customer_id,
            case_id=case.case_id,
        ):
            record = self.kill_switch.get_active_switch_record(
                action_type=action_val,
                channel=channel_val,
                customer_id=case.customer_id,
                case_id=case.case_id,
            )
            reason = record.reason if record else "Active kill switch tripped"
            return (SafetyVerdict.KILL_SWITCH_ACTIVE, f"Kill switch active: {reason}")

        # 3. Circuit Breaker Gate
        target_channel = channel_val or "GLOBAL"
        try:
            if not self.circuit_breakers.check_execution_allowed(target_channel, current_time=now):
                return (
                    SafetyVerdict.CIRCUIT_BROKEN,
                    f"Circuit breaker for channel '{target_channel}' is OPEN or saturated.",
                )
        except CircuitBrokenError as exc:
            return (
                SafetyVerdict.CIRCUIT_BROKEN,
                f"Circuit breaker for channel '{target_channel}' is OPEN: {str(exc)}",
            )

        # 4. Capacity Governor Gate
        amount = decision.parameters.get("amount_in_cents", 0)
        try:
            self.capacity_governor.check_capacity_available(
                requested_amount_in_cents=amount, current_time=now
            )
        except CapacityExceededError as exc:
            return (SafetyVerdict.CAPACITY_EXCEEDED, str(exc))

        return (SafetyVerdict.PASS, "Safety controls clear.")

    def _evaluate_compliance(
        self,
        case: RecoveryCase,
        diagnosis: DiagnosisResult,
        decision: DecisionArtifact,
        policy_id: Optional[str],
        now: datetime,
    ) -> tuple[ComplianceVerdict, str]:
        """Evaluates Policy Engine and Compliance Scheduler state (INV-07, INV-08)."""
        # 1. Policy Engine Evaluation
        policy_res: PolicyEvaluationResult = self.policy_engine.evaluate(
            case=case,
            diagnosis=diagnosis,
            decision=decision,
            policy_id=policy_id,
            current_time=now,
        )
        if not policy_res.is_allowed:
            violation_str = "; ".join(policy_res.violated_rules)
            return (
                ComplianceVerdict.BLOCKED,
                f"Policy Engine rejected decision: {violation_str}",
            )

        # 2. Compliance Scheduler Pending / Cooling-Off Obligations Check
        pending_obs = self.scheduler.get_pending_obligations(case_id=case.case_id, as_of=now)
        for ob in pending_obs:
            ob_type = getattr(ob.obligation_type, "value", str(ob.obligation_type))
            # Cooling-off or unfulfilled mandatory disclosure defers execution
            if ob_type in {
                ObligationType.COOLING_OFF.value,
                ObligationType.MANDATORY_DISCLOSURE.value,
            }:
                return (
                    ComplianceVerdict.DEFERRED,
                    f"Compliance obligation '{ob_type}' ({ob.obligation_id}) is active until {ob.scheduled_time.isoformat()}.",
                )

        return (ComplianceVerdict.APPROVED, "Policy and compliance requirements satisfied.")

    def _record_audit_event(self, record: ArbitrationRecord, now: datetime) -> None:
        """Appends an ARBITRATION_EVALUATED event to the audit logger if configured (INV-18)."""
        if self.audit_logger is not None:
            verdict_str = getattr(record.arbitrated_outcome, "value", str(record.arbitrated_outcome))
            exp_str = getattr(record.experiment_assignment, "value", str(record.experiment_assignment))
            event = ArbitrationEvaluatedEvent(
                case_id=record.case_id,
                arbitration_id=record.arbitration_id,
                verdict=verdict_str,
                experiment_state=exp_str,
                arbitration_hash=record.arbitration_hash,
                occurred_at=now,
            )
            self.audit_logger.append(
                event_type="ARBITRATION_EVALUATED",
                payload=event.model_dump(mode="json"),
                timestamp=now,
            )
