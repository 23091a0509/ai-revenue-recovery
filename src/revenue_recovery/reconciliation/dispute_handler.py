"""Settlement and Dispute Reconciliation Engine (TICKET-24).

Architecture Baseline: Frozen Architecture Baseline v11.
Enforces:
- INV-01: AI recommends; it does not execute (Reconciliation handles payment webhooks only).
- INV-02: Least-privilege authority boundaries (Accounting/Reconciliation layer with zero execution/token-minting authority).
- INV-11: Gross recovered != Confirmed recovered (Two-stage revenue ledger requiring settlement reconciliation).
- INV-12: Dispute & chargeback financial tracking (Dispute webhooks adjust net confirmed revenue to negative/loss).
- INV-18: Complete audit logging of financial transitions via append-only cryptographic logger.
"""

from datetime import datetime, timezone
from enum import Enum
import threading
from typing import Any, Optional
import uuid
from pydantic import Field, field_validator, model_validator

from src.revenue_recovery.foundation.audit import CryptographicAuditLogger
from src.revenue_recovery.foundation.events import ImmutableBaseModel
from src.revenue_recovery.reconciliation.ledger import (
    FinancialState,
    RevenueLedger,
    RevenueLedgerEntry,
)


# ============================================================================
# Core Dispute Enums (v11 Baseline §3.8, §5.3)
# ============================================================================

class DisputeReason(str, Enum):
    """Standard payment gateway dispute / chargeback reason codes."""
    FRAUDULENT = "FRAUDULENT"
    UNRECOGNIZED_CHARGE = "UNRECOGNIZED_CHARGE"
    PRODUCT_NOT_RECEIVED = "PRODUCT_NOT_RECEIVED"
    DUPLICATE_CHARGE = "DUPLICATE_CHARGE"
    SUBSCRIPTION_CANCELED = "SUBSCRIPTION_CANCELED"
    GENERAL = "GENERAL"


class DisputeStage(str, Enum):
    """Lifecycle stages for chargeback dispute arbitration."""
    NEEDS_RESPONSE = "NEEDS_RESPONSE"
    UNDER_REVIEW = "UNDER_REVIEW"
    LOST = "LOST"
    WON = "WON"


# ============================================================================
# Core Webhook & Event Domain Models
# ============================================================================

class SettlementWebhook(ImmutableBaseModel):
    """Asynchronous gateway settlement payout notification webhook."""
    event_id: str = Field(min_length=1)
    settlement_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    execution_id: Optional[str] = None
    gross_amount: int = Field(ge=0, description="Gross amount settled in minor units")
    fee_amount: int = Field(ge=0, description="Gateway processing fees in minor units")
    net_amount: int = Field(ge=0, description="Net confirmed settlement payout in minor units")
    currency: str = Field(default="INR", min_length=3, max_length=3)
    settled_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("currency")
    @classmethod
    def validate_currency(cls, v: str) -> str:
        v_upper = v.upper()
        if not v_upper.isalpha() or len(v_upper) != 3:
            raise ValueError("Currency must be a 3-letter ISO code (e.g. INR, USD)")
        return v_upper

    @model_validator(mode="after")
    def validate_net_settlement_amounts(self) -> "SettlementWebhook":
        if self.gross_amount < 0 or self.fee_amount < 0 or self.net_amount < 0:
            raise ValueError("Settlement amounts cannot be negative")
        expected_net = self.gross_amount - self.fee_amount
        if self.net_amount != expected_net:
            raise ValueError(
                f"Settlement reconciliation invariant violated: "
                f"net_amount ({self.net_amount}) must equal gross_amount ({self.gross_amount}) - fee_amount ({self.fee_amount}) = {expected_net}"
            )
        if self.net_amount > self.gross_amount:
            raise ValueError("net_amount cannot exceed gross_amount")
        return self


class DisputeWebhook(ImmutableBaseModel):
    """Asynchronous payment processor chargeback / dispute notification webhook."""
    event_id: str = Field(min_length=1)
    dispute_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    execution_id: Optional[str] = None
    disputed_amount: int = Field(gt=0, description="Disputed transaction amount in minor units")
    fee_amount: int = Field(default=0, ge=0, description="Chargeback dispute fee in minor units")
    currency: str = Field(default="INR", min_length=3, max_length=3)
    reason: DisputeReason
    stage: DisputeStage
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("currency")
    @classmethod
    def validate_currency(cls, v: str) -> str:
        v_upper = v.upper()
        if not v_upper.isalpha() or len(v_upper) != 3:
            raise ValueError("Currency must be a 3-letter ISO code (e.g. INR, USD)")
        return v_upper


class SettlementReconciledEvent(ImmutableBaseModel):
    """Domain event emitted upon successful settlement reconciliation (v11 §4)."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    settlement_id: str
    gross_amount: int
    fee_amount: int
    net_amount: int
    state: str = FinancialState.CONFIRMED_SETTLED.value
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DisputeReconciledEvent(ImmutableBaseModel):
    """Domain event emitted upon dispute/chargeback reconciliation (v11 §4)."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    dispute_id: str
    disputed_amount: int
    fee_amount: int
    reason: str
    state: str
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# Settlement & Dispute Handler Service
# ============================================================================

class SettlementDisputeHandler:
    """
    Settlement & Dispute Reconciliation Engine.
    
    Processes asynchronous settlement payouts, dispute notifications, and refunds.
    Coordinates with RevenueLedger to maintain two-stage accounting (INV-11)
    and dispute loss tracking (INV-12).
    
    Architectural Boundaries (v11 Baseline):
    - Read Access: Settlement & Dispute webhooks.
    - Decision Role: Financial state reconciliation.
    - Authorize Role: None (Zero token minting capabilities).
    - Execute Role: None (Zero execution or provider calling capabilities).
    - Network Egress: None / Internal DB only.
    """

    def __init__(
        self,
        ledger: RevenueLedger,
        audit_logger: Optional[CryptographicAuditLogger] = None,
    ) -> None:
        self.ledger: RevenueLedger = ledger
        self.audit_logger: Optional[CryptographicAuditLogger] = audit_logger
        self._lock = threading.RLock()
        self._processed_webhooks: dict[str, RevenueLedgerEntry] = {}

    def is_webhook_processed(self, event_id: str) -> bool:
        """Thread-safe check for webhook idempotency."""
        with self._lock:
            return event_id in self._processed_webhooks

    def process_settlement(self, webhook: SettlementWebhook) -> RevenueLedgerEntry:
        """
        Reconciles a gateway settlement payout webhook.
        Enforces INV-11 (Stage 2: CONFIRMED_SETTLED), deduplicates duplicate webhooks,
        records ledger entry, and emits audit event.
        """
        with self._lock:
            # Idempotency check
            if webhook.event_id in self._processed_webhooks:
                return self._processed_webhooks[webhook.event_id]

            # In two-stage accounting, settlement records verified confirmed revenue
            entry = self.ledger.record_confirmed_settlement(
                case_id=webhook.case_id,
                gross_amount=webhook.gross_amount,
                net_confirmed_amount=webhook.net_amount,
                currency=webhook.currency,
                execution_id=webhook.execution_id,
                settlement_reference=f"settlement_{webhook.settlement_id}",
                current_time=webhook.settled_at,
            )

            self._record_settlement_audit_event(webhook)
            self._processed_webhooks[webhook.event_id] = entry
            return entry

    def process_dispute(self, webhook: DisputeWebhook) -> RevenueLedgerEntry:
        """
        Reconciles a payment processor chargeback / dispute webhook.
        Enforces INV-12 (DISPUTED or WRITTEN_OFF), adjusts confirmed revenue to 0,
        records ledger entry, and emits audit event.
        """
        with self._lock:
            # Idempotency check
            if webhook.event_id in self._processed_webhooks:
                return self._processed_webhooks[webhook.event_id]

            stage_val = (
                webhook.stage.value
                if isinstance(webhook.stage, DisputeStage)
                else str(webhook.stage)
            )

            # If dispute stage is LOST, record WRITTEN_OFF (final financial loss)
            # If dispute stage is WON, case is restored to CONFIRMED_SETTLED
            # Otherwise (NEEDS_RESPONSE, UNDER_REVIEW), record DISPUTED
            if stage_val == DisputeStage.LOST.value:
                target_state = FinancialState.WRITTEN_OFF
            elif stage_val == DisputeStage.WON.value:
                target_state = FinancialState.CONFIRMED_SETTLED
            else:
                target_state = FinancialState.DISPUTED

            if target_state == FinancialState.CONFIRMED_SETTLED:
                # Restoring revenue upon winning dispute
                entry = self.ledger.record_confirmed_settlement(
                    case_id=webhook.case_id,
                    gross_amount=webhook.disputed_amount,
                    net_confirmed_amount=webhook.disputed_amount,
                    currency=webhook.currency,
                    execution_id=webhook.execution_id,
                    settlement_reference=f"dispute_won_{webhook.dispute_id}",
                    current_time=webhook.occurred_at,
                )
            else:
                entry = self.ledger.record_entry(
                    case_id=webhook.case_id,
                    financial_state=target_state,
                    gross_amount=webhook.disputed_amount,
                    net_confirmed_amount=0,
                    currency=webhook.currency,
                    execution_id=webhook.execution_id,
                    reconciliation_reference=f"dispute_{webhook.dispute_id}_{stage_val}",
                    current_time=webhook.occurred_at,
                )

            self._record_dispute_audit_event(webhook, target_state)
            self._processed_webhooks[webhook.event_id] = entry
            return entry

    def process_refund(
        self,
        case_id: str,
        refund_amount: int,
        currency: str = "INR",
        reference: str = "",
        execution_id: Optional[str] = None,
        current_time: Optional[datetime] = None,
    ) -> RevenueLedgerEntry:
        """
        Reconciles a merchant refund transaction.
        Appends FinancialState.REFUNDED entry with net_confirmed_amount = 0.
        """
        if refund_amount <= 0:
            raise ValueError(f"refund_amount must be positive, got {refund_amount}")

        now = current_time or datetime.now(timezone.utc)
        with self._lock:
            return self.ledger.record_entry(
                case_id=case_id,
                financial_state=FinancialState.REFUNDED,
                gross_amount=refund_amount,
                net_confirmed_amount=0,
                currency=currency,
                execution_id=execution_id,
                reconciliation_reference=reference or f"refund_{case_id}_{now.strftime('%Y%m%d%H%M%S')}",
                current_time=now,
            )

    def _record_settlement_audit_event(self, webhook: SettlementWebhook) -> None:
        """Emits SETTLEMENT_RECONCILED audit event (INV-18)."""
        if self.audit_logger is not None:
            event = SettlementReconciledEvent(
                case_id=webhook.case_id,
                settlement_id=webhook.settlement_id,
                gross_amount=webhook.gross_amount,
                fee_amount=webhook.fee_amount,
                net_amount=webhook.net_amount,
                state=FinancialState.CONFIRMED_SETTLED.value,
                occurred_at=webhook.settled_at,
            )
            self.audit_logger.append(
                event_type="SETTLEMENT_RECONCILED",
                payload=event.model_dump(mode="json"),
                timestamp=webhook.settled_at,
            )

    def _record_dispute_audit_event(
        self, webhook: DisputeWebhook, target_state: FinancialState
    ) -> None:
        """Emits DISPUTE_RECONCILED audit event (INV-18)."""
        if self.audit_logger is not None:
            reason_str = (
                webhook.reason.value
                if isinstance(webhook.reason, DisputeReason)
                else str(webhook.reason)
            )
            state_str = (
                target_state.value
                if isinstance(target_state, FinancialState)
                else str(target_state)
            )
            event = DisputeReconciledEvent(
                case_id=webhook.case_id,
                dispute_id=webhook.dispute_id,
                disputed_amount=webhook.disputed_amount,
                fee_amount=webhook.fee_amount,
                reason=reason_str,
                state=state_str,
                occurred_at=webhook.occurred_at,
            )
            self.audit_logger.append(
                event_type="DISPUTE_RECONCILED",
                payload=event.model_dump(mode="json"),
                timestamp=webhook.occurred_at,
            )
