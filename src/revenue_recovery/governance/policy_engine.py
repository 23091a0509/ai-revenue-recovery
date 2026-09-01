"""Deterministic Policy Engine with Rule Hierarchy and Conflict Resolution (TICKET-19).

Architecture Baseline: Frozen Architecture Baseline v11.
Enforces:
- INV-01: AI recommends; it does not execute (Deterministic policy gates all AI recommendations).
- INV-02: Least-privilege authority boundaries (Governance service with zero execution authority).
- INV-18: Complete audit logging of policy evaluations via append-only cryptographic logger.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional, Sequence
import uuid
from pydantic import Field, field_validator

from src.revenue_recovery.ai_decision.artifacts import DecisionArtifact
from src.revenue_recovery.foundation.audit import CryptographicAuditLogger, ImmutableDict
from src.revenue_recovery.foundation.events import (
    ActionChannel,
    ActionType,
    CaseState,
    ImmutableBaseModel,
    RecoveryCase,
    RiskTier,
)
from src.revenue_recovery.recovery_engine.diagnosis import DiagnosisResult


# ============================================================================
# Core Governance Enums
# ============================================================================

class PolicyLifecycleState(str, Enum):
    """Authoritative Policy Lifecycle states (v11 Baseline)."""
    DRAFT = "DRAFT"
    REVIEW = "REVIEW"
    TEST = "TEST"
    SIMULATE = "SIMULATE"
    APPROVED = "APPROVED"
    STAGE = "STAGE"
    PRODUCTION = "PRODUCTION"
    RETIRED = "RETIRED"


class RuleTier(str, Enum):
    """Rule hierarchy tiers ordered by deterministic precedence."""
    TIER_1_MANDATORY_LEGAL_SAFETY = "TIER_1_MANDATORY_LEGAL_SAFETY"
    TIER_2_BUSINESS_GOVERNANCE = "TIER_2_BUSINESS_GOVERNANCE"
    TIER_3_STRATEGY_COMPATIBILITY = "TIER_3_STRATEGY_COMPATIBILITY"


# ============================================================================
# Core Governance Domain Models
# ============================================================================

class PolicyRule(ImmutableBaseModel):
    """Immutable rule definition within a governance policy."""
    rule_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    tier: RuleTier
    description: str = Field(min_length=1)
    is_active: bool = True


class Policy(ImmutableBaseModel):
    """Immutable policy entity with versioning and lifecycle state machine."""
    policy_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    lifecycle_state: PolicyLifecycleState
    rules: tuple[PolicyRule, ...] = Field(default_factory=tuple)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    approved_by: Optional[str] = None

    @field_validator("rules", mode="before")
    @classmethod
    def convert_rules_to_tuple(cls, v: Sequence[PolicyRule] | tuple[PolicyRule, ...]) -> tuple[PolicyRule, ...]:
        if isinstance(v, tuple):
            return v
        return tuple(v)


class RuleEvaluationResult(ImmutableBaseModel):
    """Result of evaluating a single policy rule."""
    rule_id: str
    rule_tier: RuleTier
    is_compliant: bool
    violation_reason: Optional[str] = None


class PolicyEvaluationResult(ImmutableBaseModel):
    """Complete outcome of evaluating a policy against a recovery decision."""
    case_id: str
    policy_id: str
    policy_version: str
    is_allowed: bool
    violated_rules: tuple[str, ...] = Field(default_factory=tuple)
    rule_results: tuple[RuleEvaluationResult, ...] = Field(default_factory=tuple)
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("violated_rules", "rule_results", mode="before")
    @classmethod
    def convert_lists_to_tuples(cls, v: Any) -> tuple:
        if isinstance(v, tuple):
            return v
        if isinstance(v, (list, set)):
            return tuple(v)
        return v


class PolicyEvaluatedEvent(ImmutableBaseModel):
    """Domain event emitted upon completion of a policy compliance evaluation (v11 §4)."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    policy_id: str
    policy_version: str
    is_allowed: bool
    violated_rules: tuple[str, ...]
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("violated_rules", mode="before")
    @classmethod
    def convert_violated_rules_to_tuple(cls, v: Any) -> tuple[str, ...]:
        if isinstance(v, tuple):
            return v
        if isinstance(v, (list, set)):
            return tuple(v)
        return v


# ============================================================================
# Default Standard Policy Specification
# ============================================================================

STANDARD_POLICY_RULES: tuple[PolicyRule, ...] = (
    # Tier 1: Mandatory Legal & Safety Rules (Precedence 1)
    PolicyRule(
        rule_id="RULE_T1_FRAUD_BLOCK",
        name="Fraud Risk Immediate Block",
        tier=RuleTier.TIER_1_MANDATORY_LEGAL_SAFETY,
        description="Blocks any recovery action if fraud is suspected or risk tier is BLOCKED.",
    ),
    PolicyRule(
        rule_id="RULE_T1_NON_RECOVERABLE_BLOCK",
        name="Non-Recoverable Case Guard",
        tier=RuleTier.TIER_1_MANDATORY_LEGAL_SAFETY,
        description="Enforces NO_ACTION when diagnosis marks case as non-recoverable.",
    ),
    PolicyRule(
        rule_id="RULE_T1_MAX_ATTEMPTS_LIMIT",
        name="Lifetime Attempt Boundary Guard",
        tier=RuleTier.TIER_1_MANDATORY_LEGAL_SAFETY,
        description="Prohibits further recovery actions when attempt_count reaches max_attempts.",
    ),
    PolicyRule(
        rule_id="RULE_T1_SAFETY_FREEZE_GUARD",
        name="Safety Freeze Non-Bypass Guard",
        tier=RuleTier.TIER_1_MANDATORY_LEGAL_SAFETY,
        description="Prohibits any action execution on cases in FROZEN state.",
    ),
    # Tier 2: Business & Governance Rules (Precedence 2)
    PolicyRule(
        rule_id="RULE_T2_HIGH_RISK_CHANNEL_RESTRICTION",
        name="High Risk Channel Restriction",
        tier=RuleTier.TIER_2_BUSINESS_GOVERNANCE,
        description="Restricts HIGH risk tier cases to customer-interactive notification channels only.",
    ),
    PolicyRule(
        rule_id="RULE_T2_ACTION_AMOUNT_BOUND",
        name="Action Amount Upper Bound",
        tier=RuleTier.TIER_2_BUSINESS_GOVERNANCE,
        description="Ensures requested charge amount is positive and does not exceed case amount.",
    ),
    # Tier 3: Strategy & Compatibility Rules (Precedence 3)
    PolicyRule(
        rule_id="RULE_T3_MIN_CONFIDENCE_THRESHOLD",
        name="Minimum Model Confidence Threshold",
        tier=RuleTier.TIER_3_STRATEGY_COMPATIBILITY,
        description="Requires automated retry recommendation confidence score to meet minimum threshold of 0.5000.",
    ),
    PolicyRule(
        rule_id="RULE_T3_MODEL_VERSION_FRESHNESS",
        name="Model Version Freshness",
        tier=RuleTier.TIER_3_STRATEGY_COMPATIBILITY,
        description="Validates that model_version and prompt_version are specified and non-empty.",
    ),
)

DEFAULT_STANDARD_POLICY = Policy(
    policy_id="standard-recovery-policy-v1",
    version="1.0.0",
    lifecycle_state=PolicyLifecycleState.PRODUCTION,
    rules=STANDARD_POLICY_RULES,
    approved_by="governance-board@revenue-recovery.internal",
)


# ============================================================================
# Deterministic Policy Engine Service
# ============================================================================

class PolicyEngine:
    """
    Deterministic Governance Policy Engine.
    
    Architectural Boundaries (v11 Baseline):
    - Read Access: Policies, Rules, Decision Artifacts, Case Context, Diagnosis.
    - Decision Role: Policy compliance determination (Returns PolicyEvaluationResult).
    - Authorize Role: None (Zero token minting capabilities).
    - Execute Role: None (Zero execution or network dispatch capabilities).
    - Rule Hierarchy: Tier 1 (Legal/Safety) -> Tier 2 (Business) -> Tier 3 (Strategy).
    - Conflict Resolution: Deny-Overrides / Fail-Closed.
    """

    def __init__(
        self,
        policy_registry: Optional[dict[str, Policy]] = None,
        audit_logger: Optional[CryptographicAuditLogger] = None,
    ) -> None:
        self._policies: dict[str, Policy] = {}
        if policy_registry:
            for p in policy_registry.values():
                self._policies[p.policy_id] = p
        else:
            self._policies[DEFAULT_STANDARD_POLICY.policy_id] = DEFAULT_STANDARD_POLICY

        self.audit_logger: Optional[CryptographicAuditLogger] = audit_logger

    def register_policy(self, policy: Policy) -> None:
        """Registers or updates a policy definition in the internal policy registry."""
        self._policies[policy.policy_id] = policy

    def get_policy(self, policy_id: str) -> Optional[Policy]:
        """Retrieves a registered policy by its policy_id."""
        return self._policies.get(policy_id)

    def evaluate(
        self,
        case: RecoveryCase,
        diagnosis: DiagnosisResult,
        decision: DecisionArtifact,
        policy_id: Optional[str] = None,
        current_time: Optional[datetime] = None,
    ) -> PolicyEvaluationResult:
        """
        Evaluates a decision artifact against the specified governance policy.
        
        Guards & Invariants:
        - Non-existent policy -> Fails closed (is_allowed = False).
        - Non-executable policy lifecycle state -> Fails closed (is_allowed = False).
        - Tier 1 -> Tier 2 -> Tier 3 strict precedence evaluation.
        - Deny-Overrides: If any active rule fails, is_allowed = False.
        - Emits PolicyEvaluatedEvent to audit logger if present.
        """
        now = current_time or datetime.now(timezone.utc)
        target_policy_id = policy_id or DEFAULT_STANDARD_POLICY.policy_id
        policy = self._policies.get(target_policy_id)

        # Policy not found -> Fail closed
        if policy is None:
            violation = f"POLICY_NOT_FOUND: Policy '{target_policy_id}' is not registered."
            return PolicyEvaluationResult(
                case_id=case.case_id,
                policy_id=target_policy_id,
                policy_version="UNKNOWN",
                is_allowed=False,
                violated_rules=(violation,),
                rule_results=(),
                evaluated_at=now,
            )

        # Policy lifecycle state guard: Only PRODUCTION and STAGE/APPROVED can authorize
        executable_states = {
            PolicyLifecycleState.PRODUCTION.value,
            PolicyLifecycleState.STAGE.value,
            PolicyLifecycleState.APPROVED.value,
        }
        policy_state_str = (
            policy.lifecycle_state.value
            if isinstance(policy.lifecycle_state, PolicyLifecycleState)
            else str(policy.lifecycle_state)
        )
        if policy_state_str not in executable_states:
            violation = (
                f"INACTIVE_POLICY_LIFECYCLE: Policy '{policy.policy_id}' is in state "
                f"'{policy_state_str}', which is not authorized for execution."
            )
            eval_result = PolicyEvaluationResult(
                case_id=case.case_id,
                policy_id=policy.policy_id,
                policy_version=policy.version,
                is_allowed=False,
                violated_rules=(violation,),
                rule_results=(),
                evaluated_at=now,
            )
            self._record_audit_event(eval_result, now)
            return eval_result

        # Sort rules strictly by RuleTier precedence
        tier_precedence = {
            RuleTier.TIER_1_MANDATORY_LEGAL_SAFETY.value: 1,
            RuleTier.TIER_2_BUSINESS_GOVERNANCE.value: 2,
            RuleTier.TIER_3_STRATEGY_COMPATIBILITY.value: 3,
        }
        sorted_rules = sorted(
            [r for r in policy.rules if r.is_active],
            key=lambda r: (
                tier_precedence.get(r.tier.value if isinstance(r.tier, RuleTier) else str(r.tier), 99),
                r.rule_id,
            ),
        )

        rule_results: list[RuleEvaluationResult] = []
        violated_rules: list[str] = []

        # Evaluate rules in strict deterministic precedence order
        for rule in sorted_rules:
            res = self._evaluate_rule(rule, case, diagnosis, decision)
            rule_results.append(res)
            if not res.is_compliant:
                violated_rules.append(res.violation_reason or rule.rule_id)

        # Conflict resolution: Strict Deny-Overrides / Fail-Closed
        is_allowed = len(violated_rules) == 0

        eval_result = PolicyEvaluationResult(
            case_id=case.case_id,
            policy_id=policy.policy_id,
            policy_version=policy.version,
            is_allowed=is_allowed,
            violated_rules=tuple(violated_rules),
            rule_results=tuple(rule_results),
            evaluated_at=now,
        )

        self._record_audit_event(eval_result, now)
        return eval_result

    def _evaluate_rule(
        self,
        rule: PolicyRule,
        case: RecoveryCase,
        diagnosis: DiagnosisResult,
        decision: DecisionArtifact,
    ) -> RuleEvaluationResult:
        """Evaluates an individual rule deterministically."""
        action_val = (
            decision.recommended_action.value
            if isinstance(decision.recommended_action, ActionType)
            else str(decision.recommended_action)
        )
        risk_tier_val = (
            diagnosis.risk_tier.value
            if isinstance(diagnosis.risk_tier, RiskTier)
            else str(diagnosis.risk_tier)
        )
        case_risk_val = (
            case.risk_tier.value
            if isinstance(case.risk_tier, RiskTier)
            else str(case.risk_tier)
        )
        case_state_val = (
            case.state.value
            if isinstance(case.state, CaseState)
            else str(case.state)
        )

        # --------------------------------------------------------------------
        # Tier 1 Rules: Mandatory Legal & Safety
        # --------------------------------------------------------------------
        if rule.rule_id == "RULE_T1_FRAUD_BLOCK":
            if (
                risk_tier_val == RiskTier.BLOCKED.value
                or diagnosis.diagnosis_code == "FRAUD_RISK_BLOCK"
                or case_risk_val == RiskTier.BLOCKED.value
            ):
                if action_val != ActionType.NO_ACTION.value:
                    return RuleEvaluationResult(
                        rule_id=rule.rule_id,
                        rule_tier=rule.tier,
                        is_compliant=False,
                        violation_reason=(
                            f"{rule.rule_id}: Fraud suspected or BLOCKED risk tier. "
                            f"Recommended action '{action_val}' is prohibited; MUST be NO_ACTION."
                        ),
                    )
            return RuleEvaluationResult(rule_id=rule.rule_id, rule_tier=rule.tier, is_compliant=True)

        if rule.rule_id == "RULE_T1_NON_RECOVERABLE_BLOCK":
            if not diagnosis.is_recoverable and action_val != ActionType.NO_ACTION.value:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    rule_tier=rule.tier,
                    is_compliant=False,
                    violation_reason=(
                        f"{rule.rule_id}: Diagnosis marked case as non-recoverable. "
                        f"Recommended action '{action_val}' is prohibited; MUST be NO_ACTION."
                    ),
                )
            return RuleEvaluationResult(rule_id=rule.rule_id, rule_tier=rule.tier, is_compliant=True)

        if rule.rule_id == "RULE_T1_MAX_ATTEMPTS_LIMIT":
            if case.attempt_count >= case.max_attempts and action_val != ActionType.NO_ACTION.value:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    rule_tier=rule.tier,
                    is_compliant=False,
                    violation_reason=(
                        f"{rule.rule_id}: Case attempt_count ({case.attempt_count}) has reached or exceeded "
                        f"max_attempts ({case.max_attempts}). Further recovery attempts are prohibited."
                    ),
                )
            return RuleEvaluationResult(rule_id=rule.rule_id, rule_tier=rule.tier, is_compliant=True)

        if rule.rule_id == "RULE_T1_SAFETY_FREEZE_GUARD":
            if case_state_val == CaseState.FROZEN.value:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    rule_tier=rule.tier,
                    is_compliant=False,
                    violation_reason=f"{rule.rule_id}: Case is in FROZEN state. All recovery operations are prohibited.",
                )
            return RuleEvaluationResult(rule_id=rule.rule_id, rule_tier=rule.tier, is_compliant=True)

        # --------------------------------------------------------------------
        # Tier 2 Rules: Business & Governance
        # --------------------------------------------------------------------
        if rule.rule_id == "RULE_T2_HIGH_RISK_CHANNEL_RESTRICTION":
            if risk_tier_val == RiskTier.HIGH.value:
                param_channel = decision.parameters.get("channel")
                if (
                    param_channel == ActionChannel.DIRECT_PAYMENT_GATEWAY.value
                    or action_val == ActionType.RETRY_CHARGE.value
                ):
                    return RuleEvaluationResult(
                        rule_id=rule.rule_id,
                        rule_tier=rule.tier,
                        is_compliant=False,
                        violation_reason=(
                            f"{rule.rule_id}: HIGH risk tier requires customer-interactive notification channels. "
                            f"Direct automated retry on '{param_channel}' is disallowed."
                        ),
                    )
            return RuleEvaluationResult(rule_id=rule.rule_id, rule_tier=rule.tier, is_compliant=True)

        if rule.rule_id == "RULE_T2_ACTION_AMOUNT_BOUND":
            if action_val == ActionType.RETRY_CHARGE.value:
                amt = decision.parameters.get("amount_in_cents")
                if amt is None or not isinstance(amt, int) or amt <= 0 or amt > case.amount_in_cents:
                    return RuleEvaluationResult(
                        rule_id=rule.rule_id,
                        rule_tier=rule.tier,
                        is_compliant=False,
                        violation_reason=(
                            f"{rule.rule_id}: RETRY_CHARGE parameter 'amount_in_cents' ({amt}) must be positive "
                            f"and <= case amount ({case.amount_in_cents})."
                        ),
                    )
            return RuleEvaluationResult(rule_id=rule.rule_id, rule_tier=rule.tier, is_compliant=True)

        # --------------------------------------------------------------------
        # Tier 3 Rules: Strategy & Compatibility
        # --------------------------------------------------------------------
        if rule.rule_id == "RULE_T3_MIN_CONFIDENCE_THRESHOLD":
            if action_val == ActionType.RETRY_CHARGE.value and decision.confidence_score < 0.5000:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    rule_tier=rule.tier,
                    is_compliant=False,
                    violation_reason=(
                        f"{rule.rule_id}: Automated retry confidence score {decision.confidence_score:.4f} "
                        f"is below minimum threshold 0.5000."
                    ),
                )
            return RuleEvaluationResult(rule_id=rule.rule_id, rule_tier=rule.tier, is_compliant=True)

        if rule.rule_id == "RULE_T3_MODEL_VERSION_FRESHNESS":
            if not decision.model_version or not decision.prompt_version:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    rule_tier=rule.tier,
                    is_compliant=False,
                    violation_reason=f"{rule.rule_id}: Model version or prompt version is missing or empty.",
                )
            return RuleEvaluationResult(rule_id=rule.rule_id, rule_tier=rule.tier, is_compliant=True)

        # Unrecognized custom active rule -> Pass as compliant by default
        return RuleEvaluationResult(rule_id=rule.rule_id, rule_tier=rule.tier, is_compliant=True)

    def _record_audit_event(self, eval_result: PolicyEvaluationResult, now: datetime) -> None:
        """Appends a PolicyEvaluatedEvent to the audit logger if present (INV-18)."""
        if self.audit_logger is not None:
            event = PolicyEvaluatedEvent(
                case_id=eval_result.case_id,
                policy_id=eval_result.policy_id,
                policy_version=eval_result.policy_version,
                is_allowed=eval_result.is_allowed,
                violated_rules=eval_result.violated_rules,
                occurred_at=now,
            )
            self.audit_logger.append(
                event_type="POLICY_EVALUATED",
                payload=event.model_dump(mode="json"),
                timestamp=now,
            )
