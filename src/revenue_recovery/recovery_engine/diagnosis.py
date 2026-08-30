"""Deterministic Risk and Diagnosis evaluator for Recovery Cases (TICKET-14).

Architecture Baseline: Frozen Architecture Baseline v11.
Enforces:
- Pure, deterministic classification of PaymentFailureEvent instances.
- Deterministic risk scoring in [0.0, 1.0] and RiskTier assignment.
- Rule precedence and escalation for attempt counts and high-value amounts.
- Strict fail-closed validation for unknown, invalid, or fraud events.
"""

from typing import Optional
from pydantic import Field

from src.revenue_recovery.foundation.events import (
    ActionChannel,
    FailureReason,
    ImmutableBaseModel,
    PaymentFailureEvent,
    RiskTier,
)

# High-value monetary threshold in cents (e.g., 100,000 cents = 1,000 INR/USD)
HIGH_VALUE_THRESHOLD_CENTS: int = 100_000


class DiagnosisResult(ImmutableBaseModel):
    """Immutable output model of a deterministic failure diagnosis."""
    diagnosis_code: str = Field(min_length=1)
    risk_score: float = Field(ge=0.0, le=1.0)
    risk_tier: RiskTier
    is_recoverable: bool
    recommended_channel: ActionChannel
    rationale: str = Field(min_length=1)


class RiskDiagnosisEvaluator:
    """
    Deterministic rule-based evaluator that classifies payment failure root causes,
    computes numeric risk scores and RiskTier, and recommends the initial action channel.
    """

    @staticmethod
    def evaluate(
        event: PaymentFailureEvent,
        attempt_count: int = 0,
    ) -> DiagnosisResult:
        """
        Pure, deterministic diagnosis evaluation.
        Produces identical output for identical inputs with zero external dependencies.
        """
        if attempt_count < 0:
            raise ValueError(f"attempt_count must be >= 0, got {attempt_count}")

        # Rule 1: Fraud suspicion (Highest Precedence) -> Immediate BLOCK
        if event.failure_reason == FailureReason.FRAUD_SUSPECTED:
            return DiagnosisResult(
                diagnosis_code="FRAUD_RISK_BLOCK",
                risk_score=1.0,
                risk_tier=RiskTier.BLOCKED,
                is_recoverable=False,
                recommended_channel=ActionChannel.INTERNAL_SYSTEM,
                rationale="Suspected fraud detected; automated recovery blocked and routed to internal security.",
            )

        # Rule 2: 3DS / SCA Authentication Failure -> Step-up interactive required
        if event.failure_reason == FailureReason.AUTHENTICATION_FAILED:
            return DiagnosisResult(
                diagnosis_code="AUTH_STEP_UP_REQUIRED",
                risk_score=0.75,
                risk_tier=RiskTier.HIGH,
                is_recoverable=True,
                recommended_channel=ActionChannel.EMAIL,
                rationale="Customer authentication failed; interactive step-up required via notification.",
            )

        # Rule 3: Unclassified Generic Decline
        if event.failure_reason == FailureReason.GENERIC_DECLINE:
            is_high_risk = attempt_count >= 2 or event.amount_in_cents >= HIGH_VALUE_THRESHOLD_CENTS
            risk_score = 0.65 if is_high_risk else 0.50
            risk_tier = RiskTier.HIGH if is_high_risk else RiskTier.MEDIUM
            recommended_channel = ActionChannel.EMAIL if is_high_risk else ActionChannel.DIRECT_PAYMENT_GATEWAY
            code = "HIGH_RISK_GENERIC_DECLINE" if is_high_risk else "UNCLASSIFIED_DECLINE"
            rationale = (
                "Unclassified bank decline with high-risk attributes; customer notification recommended."
                if is_high_risk
                else "Unclassified bank decline; initial conservative payment retry permitted."
            )
            return DiagnosisResult(
                diagnosis_code=code,
                risk_score=risk_score,
                risk_tier=risk_tier,
                is_recoverable=True,
                recommended_channel=recommended_channel,
                rationale=rationale,
            )

        # Rule 4: Expired Card Credential
        if event.failure_reason == FailureReason.CARD_EXPIRED:
            return DiagnosisResult(
                diagnosis_code="CREDENTIAL_EXPIRED",
                risk_score=0.40,
                risk_tier=RiskTier.MEDIUM,
                is_recoverable=True,
                recommended_channel=ActionChannel.EMAIL,
                rationale="Payment card is expired; customer payment method update notification required.",
            )

        # Rule 5: Insufficient Funds (Liquidity Shortfall)
        if event.failure_reason == FailureReason.INSUFFICIENT_FUNDS:
            if attempt_count >= 2:
                return DiagnosisResult(
                    diagnosis_code="PERSISTENT_LIQUIDITY_SHORTFALL",
                    risk_score=0.35,
                    risk_tier=RiskTier.MEDIUM,
                    is_recoverable=True,
                    recommended_channel=ActionChannel.EMAIL,
                    rationale="Repeated insufficient funds failures; escalating to customer communication.",
                )
            return DiagnosisResult(
                diagnosis_code="TRANSIENT_INSUFFICIENT_FUNDS",
                risk_score=0.20,
                risk_tier=RiskTier.LOW,
                is_recoverable=True,
                recommended_channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
                rationale="Transient liquidity shortfall; eligible for automated smart retry.",
            )

        # Rule 6: Gateway Processing Error
        if event.failure_reason == FailureReason.PROCESSING_ERROR:
            return DiagnosisResult(
                diagnosis_code="GATEWAY_PROCESSING_ERROR",
                risk_score=0.10,
                risk_tier=RiskTier.LOW,
                is_recoverable=True,
                recommended_channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
                rationale="Transient gateway processing error; eligible for automated backoff retry.",
            )

        # Rule 7: Gateway Timeout
        if event.failure_reason == FailureReason.GATEWAY_TIMEOUT:
            return DiagnosisResult(
                diagnosis_code="NETWORK_GATEWAY_TIMEOUT",
                risk_score=0.05,
                risk_tier=RiskTier.LOW,
                is_recoverable=True,
                recommended_channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
                rationale="Network or gateway timeout; eligible for immediate automated retry.",
            )

        # Fallback Fail-Closed for unhandled reasons
        return DiagnosisResult(
            diagnosis_code="UNKNOWN_FAILURE_REASON_BLOCK",
            risk_score=1.0,
            risk_tier=RiskTier.BLOCKED,
            is_recoverable=False,
            recommended_channel=ActionChannel.INTERNAL_SYSTEM,
            rationale=f"Unhandled or unknown failure reason '{event.failure_reason}'; failing closed.",
        )


def evaluate_diagnosis(
    event: PaymentFailureEvent,
    attempt_count: int = 0,
) -> DiagnosisResult:
    """Convenience function delegating to RiskDiagnosisEvaluator.evaluate."""
    return RiskDiagnosisEvaluator.evaluate(event=event, attempt_count=attempt_count)
