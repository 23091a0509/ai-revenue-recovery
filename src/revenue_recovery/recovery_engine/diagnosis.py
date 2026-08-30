"""Deterministic Risk and Diagnosis evaluator for Recovery Cases (TICKET-14).

Authoritative Basis:
- Frozen Architecture Baseline v11 Requirements.
- Formal TICKET-14 Specification Amendment (Approved by Verification Manager).

Enforces:
- Pure, deterministic classification of PaymentFailureEvent instances.
- Discrete risk scores in {0.0500, 0.1000, 0.2000, 0.3500, 0.4000, 0.5000, 0.6500, 0.7500, 1.0000}.
- Authoritative RiskTier and ActionChannel assignment.
- Exact threshold boundaries: amount >= 100,000 minor units and attempt_count >= 2.
- Strict fail-closed validation for unsupported currencies, unknown reasons, and fraud.
"""

from typing import FrozenSet
from pydantic import Field

from src.revenue_recovery.foundation.events import (
    ActionChannel,
    FailureReason,
    ImmutableBaseModel,
    PaymentFailureEvent,
    RiskTier,
)

# Supported 2-decimal fiat currencies in MVP
SUPPORTED_CURRENCIES: FrozenSet[str] = frozenset({"INR", "USD", "EUR", "GBP"})

# High-value monetary threshold in minor currency units (e.g. 100,000 cents/paise)
HIGH_VALUE_THRESHOLD_UNITS: int = 100_000


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
    computes discrete numeric risk scores and RiskTier, and recommends the initial action channel.
    """

    @staticmethod
    def evaluate(
        event: PaymentFailureEvent,
        attempt_count: int = 0,
    ) -> DiagnosisResult:
        """
        Pure, deterministic diagnosis evaluation per the approved TICKET-14 specification.
        Produces identical output for identical inputs with zero external dependencies.
        """
        if attempt_count < 0:
            raise ValueError(f"attempt_count must be >= 0, got {attempt_count}")

        # Currency validation: Unsupported currencies fail closed immediately
        normalized_currency = event.currency.upper()
        if normalized_currency not in SUPPORTED_CURRENCIES:
            return DiagnosisResult(
                diagnosis_code="UNSUPPORTED_CURRENCY_BLOCK",
                risk_score=1.0000,
                risk_tier=RiskTier.BLOCKED,
                is_recoverable=False,
                recommended_channel=ActionChannel.INTERNAL_SYSTEM,
                rationale=f"Currency '{event.currency}' is unsupported; failing closed.",
            )

        # Precedence 1: Fraud suspicion (Highest Precedence) -> Immediate BLOCK
        if event.failure_reason == FailureReason.FRAUD_SUSPECTED:
            return DiagnosisResult(
                diagnosis_code="FRAUD_RISK_BLOCK",
                risk_score=1.0000,
                risk_tier=RiskTier.BLOCKED,
                is_recoverable=False,
                recommended_channel=ActionChannel.INTERNAL_SYSTEM,
                rationale="Suspected fraud detected; automated recovery blocked and routed to internal security.",
            )

        # Precedence 2: 3DS / SCA Authentication Failure -> Step-up interactive required
        if event.failure_reason == FailureReason.AUTHENTICATION_FAILED:
            return DiagnosisResult(
                diagnosis_code="AUTH_STEP_UP_REQUIRED",
                risk_score=0.7500,
                risk_tier=RiskTier.HIGH,
                is_recoverable=True,
                recommended_channel=ActionChannel.EMAIL,
                rationale="Customer authentication failed; interactive step-up required via notification.",
            )

        # Precedence 3 & 4: Unclassified Generic Decline
        if event.failure_reason == FailureReason.GENERIC_DECLINE:
            is_high_risk = (event.amount_in_cents >= HIGH_VALUE_THRESHOLD_UNITS) or (attempt_count >= 2)
            if is_high_risk:
                return DiagnosisResult(
                    diagnosis_code="HIGH_RISK_GENERIC_DECLINE",
                    risk_score=0.6500,
                    risk_tier=RiskTier.HIGH,
                    is_recoverable=True,
                    recommended_channel=ActionChannel.EMAIL,
                    rationale="Unclassified bank decline with high-risk attributes; customer notification recommended.",
                )
            return DiagnosisResult(
                diagnosis_code="UNCLASSIFIED_DECLINE",
                risk_score=0.5000,
                risk_tier=RiskTier.MEDIUM,
                is_recoverable=True,
                recommended_channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
                rationale="Unclassified bank decline; initial conservative payment retry permitted.",
            )

        # Precedence 5: Expired Card Credential
        if event.failure_reason == FailureReason.CARD_EXPIRED:
            return DiagnosisResult(
                diagnosis_code="CREDENTIAL_EXPIRED",
                risk_score=0.4000,
                risk_tier=RiskTier.MEDIUM,
                is_recoverable=True,
                recommended_channel=ActionChannel.EMAIL,
                rationale="Payment card is expired; customer payment method update notification required.",
            )

        # Precedence 6 & 7: Insufficient Funds (Liquidity Shortfall)
        if event.failure_reason == FailureReason.INSUFFICIENT_FUNDS:
            if attempt_count >= 2:
                return DiagnosisResult(
                    diagnosis_code="PERSISTENT_LIQUIDITY_SHORTFALL",
                    risk_score=0.3500,
                    risk_tier=RiskTier.MEDIUM,
                    is_recoverable=True,
                    recommended_channel=ActionChannel.EMAIL,
                    rationale="Repeated insufficient funds failures; escalating to customer communication.",
                )
            return DiagnosisResult(
                diagnosis_code="TRANSIENT_INSUFFICIENT_FUNDS",
                risk_score=0.2000,
                risk_tier=RiskTier.LOW,
                is_recoverable=True,
                recommended_channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
                rationale="Transient liquidity shortfall; eligible for automated smart retry.",
            )

        # Precedence 8: Gateway Processing Error
        if event.failure_reason == FailureReason.PROCESSING_ERROR:
            return DiagnosisResult(
                diagnosis_code="GATEWAY_PROCESSING_ERROR",
                risk_score=0.1000,
                risk_tier=RiskTier.LOW,
                is_recoverable=True,
                recommended_channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
                rationale="Transient gateway processing error; eligible for automated backoff retry.",
            )

        # Precedence 9: Gateway Timeout
        if event.failure_reason == FailureReason.GATEWAY_TIMEOUT:
            return DiagnosisResult(
                diagnosis_code="NETWORK_GATEWAY_TIMEOUT",
                risk_score=0.0500,
                risk_tier=RiskTier.LOW,
                is_recoverable=True,
                recommended_channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
                rationale="Network or gateway timeout; eligible for immediate automated retry.",
            )

        # Fallback Fail-Closed for unhandled or unrecognized reasons
        return DiagnosisResult(
            diagnosis_code="UNKNOWN_FAILURE_REASON_BLOCK",
            risk_score=1.0000,
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
