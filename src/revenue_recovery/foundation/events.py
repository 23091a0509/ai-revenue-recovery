"""Core domain models, state enums, and immutable event contracts for AI Revenue Recovery MVP.

Architecture Baseline: Frozen Architecture Baseline v11.
All models are strictly typed and immutable (frozen=True, extra="forbid").
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Generic, TypeVar
import uuid
from pydantic import BaseModel, ConfigDict, Field, field_validator


# ============================================================================
# Core Domain Enums
# ============================================================================

class CaseState(str, Enum):
    """Lifecycle state machine states for a Recovery Case (v11 Baseline)."""
    OPEN = "OPEN"
    DIAGNOSED = "DIAGNOSED"
    EVALUATING = "EVALUATING"
    SCHEDULED = "SCHEDULED"
    EXECUTING = "EXECUTING"
    RECONCILING = "RECONCILING"
    RESOLVED = "RESOLVED"
    ABANDONED = "ABANDONED"
    FROZEN = "FROZEN"


class RiskTier(str, Enum):
    """Customer / case risk tier evaluating recovery feasibility and fraud risk."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    BLOCKED = "BLOCKED"


class FailureReason(str, Enum):
    """Classified payment failure root causes."""
    INSUFFICIENT_FUNDS = "INSUFFICIENT_FUNDS"
    CARD_EXPIRED = "CARD_EXPIRED"
    GATEWAY_TIMEOUT = "GATEWAY_TIMEOUT"
    PROCESSING_ERROR = "PROCESSING_ERROR"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    FRAUD_SUSPECTED = "FRAUD_SUSPECTED"
    GENERIC_DECLINE = "GENERIC_DECLINE"


class ActionType(str, Enum):
    """Allowed recovery actions within the bounded action space."""
    RETRY_CHARGE = "RETRY_CHARGE"
    SEND_NOTIFICATION = "SEND_NOTIFICATION"
    UPDATE_PAYMENT_METHOD_REQUEST = "UPDATE_PAYMENT_METHOD_REQUEST"
    OFFER_PAYMENT_PLAN = "OFFER_PAYMENT_PLAN"
    APPLY_GRACE_PERIOD = "APPLY_GRACE_PERIOD"
    NO_ACTION = "NO_ACTION"


class ActionChannel(str, Enum):
    """Communication and execution channels for recovery actions."""
    DIRECT_PAYMENT_GATEWAY = "DIRECT_PAYMENT_GATEWAY"
    EMAIL = "EMAIL"
    SMS = "SMS"
    WHATSAPP = "WHATSAPP"
    INTERNAL_SYSTEM = "INTERNAL_SYSTEM"


class ObligationType(str, Enum):
    """Mandatory compliance obligation types."""
    MANDATORY_DISCLOSURE = "MANDATORY_DISCLOSURE"
    COOLING_OFF = "COOLING_OFF"
    RETRY_WINDOW = "RETRY_WINDOW"
    CONSENT_CHECK = "CONSENT_CHECK"


class ExecutionStatus(str, Enum):
    """Execution status for an action."""
    PENDING = "PENDING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    SKIPPED = "SKIPPED"


# ============================================================================
# Core Domain Models
# ============================================================================

class ImmutableBaseModel(BaseModel):
    """Base model enforcing strict immutability and forbidding extra attributes."""
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        use_enum_values=True
    )


class PaymentFailureEvent(ImmutableBaseModel):
    """Inbound trigger event notifying the recovery system of a failed payment."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    customer_id: str = Field(min_length=1)
    invoice_id: str = Field(min_length=1)
    amount_in_cents: int = Field(gt=0, description="Amount in minor units (e.g., cents, paise)")
    currency: str = Field(default="INR", min_length=3, max_length=3)
    failure_reason: FailureReason
    failure_code: str = Field(default="GENERIC_ERROR", min_length=1)
    gateway_reference: str = Field(min_length=1)
    failed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("currency")
    @classmethod
    def validate_currency(cls, v: str) -> str:
        v_upper = v.upper()
        if not v_upper.isalpha() or len(v_upper) != 3:
            raise ValueError("Currency must be a 3-letter ISO code (e.g., INR, USD)")
        return v_upper


class RecoveryCase(ImmutableBaseModel):
    """Authoritative domain representation of a Recovery Case."""
    case_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    customer_id: str = Field(min_length=1)
    trigger_event_id: str = Field(min_length=1)
    amount_in_cents: int = Field(gt=0)
    currency: str = Field(default="INR", min_length=3, max_length=3)
    state: CaseState = Field(default=CaseState.OPEN)
    risk_tier: RiskTier = Field(default=RiskTier.LOW)
    attempt_count: int = Field(default=0, ge=0)
    max_attempts: int = Field(default=3, ge=1)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("currency")
    @classmethod
    def validate_currency(cls, v: str) -> str:
        return v.upper()


class ComplianceObligation(ImmutableBaseModel):
    """Scheduled compliance obligation linked to a Recovery Case."""
    obligation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str = Field(min_length=1)
    obligation_type: ObligationType
    is_mandatory: bool = Field(default=True)
    scheduled_time: datetime
    status: str = Field(default="PENDING", min_length=1)
    resolution_reason: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# Generic Domain Event Envelope
# ============================================================================

T = TypeVar("T")

class DomainEventEnvelope(ImmutableBaseModel, Generic[T]):
    """
    Standardized, append-only domain event envelope ensuring auditability,
    idempotency, and causal tracing across services.
    """
    envelope_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = Field(min_length=1)
    idempotency_key: str = Field(min_length=1)
    correlation_id: str = Field(min_length=1)
    causation_id: str = Field(min_length=1)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    version: str = Field(default="1.0.0")
    payload: dict[str, Any]
