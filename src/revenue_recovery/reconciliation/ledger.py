"""Append-Only Two-Stage Revenue Ledger (TICKET-23).

Architecture Baseline: Frozen Architecture Baseline v11.
Enforces:
- INV-01: AI recommends; it does not execute (Ledger provides financial accounting only).
- INV-02: Least-privilege authority boundaries (Isolated accounting layer with zero execution/token-minting authority).
- INV-11: Gross recovered != Confirmed recovered (Two-stage revenue ledger requiring settlement reconciliation).
- INV-18: Complete audit logging of financial transitions via append-only cryptographic logger.
"""

from datetime import datetime, timezone
from enum import Enum
import threading
from typing import Optional, Sequence
import uuid
from pydantic import Field, field_validator

from src.revenue_recovery.foundation.audit import CryptographicAuditLogger
from src.revenue_recovery.foundation.events import ImmutableBaseModel


# ============================================================================
# Core Financial Enums (v11 Baseline §3.8)
# ============================================================================

class FinancialState(str, Enum):
    """Authoritative financial lifecycle states for ledger transactions."""
    INITIATED = "INITIATED"
    GROSS_RECOVERED = "GROSS_RECOVERED"
    CONFIRMED_SETTLED = "CONFIRMED_SETTLED"
    DISPUTED = "DISPUTED"
    REFUNDED = "REFUNDED"
    WRITTEN_OFF = "WRITTEN_OFF"


# ============================================================================
# Core Ledger Domain Models
# ============================================================================

class RevenueLedgerEntry(ImmutableBaseModel):
    """Immutable record of an individual revenue ledger transaction (v11 §3.8)."""
    entry_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str = Field(min_length=1)
    execution_id: Optional[str] = None
    financial_state: FinancialState
    gross_amount: int = Field(ge=0, description="Gross recovery amount in minor units (e.g. cents/paise)")
    net_confirmed_amount: int = Field(default=0, ge=0, description="Confirmed settled amount in minor units")
    currency: str = Field(default="INR", min_length=3, max_length=3)
    reconciliation_reference: str = Field(default="", min_length=0)
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("currency")
    @classmethod
    def validate_currency(cls, v: str) -> str:
        v_upper = v.upper()
        if not v_upper.isalpha() or len(v_upper) != 3:
            raise ValueError("Currency must be a 3-letter ISO code (e.g. INR, USD)")
        return v_upper

    @field_validator("net_confirmed_amount")
    @classmethod
    def validate_amounts_consistency(cls, v: int, info) -> int:
        state = info.data.get("financial_state")
        gross = info.data.get("gross_amount", 0)

        # Extract string value if enum
        state_str = getattr(state, "value", str(state)) if state is not None else None

        # Stage 1: INITIATED or GROSS_RECOVERED MUST have net_confirmed_amount == 0 (INV-11)
        if state_str in {FinancialState.INITIATED.value, FinancialState.GROSS_RECOVERED.value}:
            if v != 0:
                raise ValueError(
                    f"Two-stage accounting invariant violated (INV-11): "
                    f"State '{state_str}' represents unconfirmed gross recovery and MUST have net_confirmed_amount == 0, got {v}"
                )

        # Stage 2: CONFIRMED_SETTLED requires net_confirmed_amount > 0 and <= gross_amount
        if state_str == FinancialState.CONFIRMED_SETTLED.value:
            if v <= 0:
                raise ValueError(
                    f"CONFIRMED_SETTLED state requires positive net_confirmed_amount, got {v}"
                )
            if v > gross:
                raise ValueError(
                    f"Two-stage accounting invariant violated: "
                    f"net_confirmed_amount ({v}) cannot exceed gross_amount ({gross})"
                )

        return v


class LedgerSummary(ImmutableBaseModel):
    """Immutable aggregate financial summary for a Recovery Case."""
    case_id: str = Field(min_length=1)
    currency: str = Field(min_length=3, max_length=3)
    total_gross_recovered: int = Field(ge=0)
    total_net_confirmed: int = Field(ge=0)
    latest_state: FinancialState
    entry_count: int = Field(ge=0)
    computed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class LedgerEntryRecordedEvent(ImmutableBaseModel):
    """Domain event emitted upon recording a new immutable ledger entry (v11 §4)."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entry_id: str
    case_id: str
    financial_state: str
    gross_amount: int
    net_confirmed_amount: int
    currency: str
    reconciliation_reference: str
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# Revenue Ledger Service
# ============================================================================

class RevenueLedger:
    """
    Append-Only Two-Stage Revenue Ledger Service.
    
    Enforces INV-11:
    Stage 1: GROSS_RECOVERED (Unconfirmed gross revenue, net_confirmed_amount = 0).
    Stage 2: CONFIRMED_SETTLED (Verified settlement reconciliation, net_confirmed_amount > 0).
    
    Architectural Boundaries (v11 Baseline):
    - Read Access: Execution records, Settlement/Dispute webhooks.
    - Decision Role: Financial state reconciliation & ledger accounting.
    - Authorize Role: None (Zero token minting capabilities).
    - Execute Role: None (Zero execution or provider calling capabilities).
    - Network Egress: None / Internal DB only.
    """

    def __init__(
        self,
        audit_logger: Optional[CryptographicAuditLogger] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._entries: list[RevenueLedgerEntry] = []
        self.audit_logger: Optional[CryptographicAuditLogger] = audit_logger

    def record_entry(
        self,
        case_id: str,
        financial_state: FinancialState | str,
        gross_amount: int,
        net_confirmed_amount: int = 0,
        currency: str = "INR",
        execution_id: Optional[str] = None,
        reconciliation_reference: str = "",
        current_time: Optional[datetime] = None,
    ) -> RevenueLedgerEntry:
        """
        Appends an immutable financial transaction entry to the ledger.
        Validates two-stage invariants and emits audit event.
        """
        now = current_time or datetime.now(timezone.utc)
        if gross_amount < 0:
            raise ValueError(f"gross_amount cannot be negative, got {gross_amount}")
        if net_confirmed_amount < 0:
            raise ValueError(f"net_confirmed_amount cannot be negative, got {net_confirmed_amount}")

        state_enum = (
            financial_state
            if isinstance(financial_state, FinancialState)
            else FinancialState(str(financial_state))
        )

        entry = RevenueLedgerEntry(
            case_id=case_id,
            execution_id=execution_id,
            financial_state=state_enum,
            gross_amount=gross_amount,
            net_confirmed_amount=net_confirmed_amount,
            currency=currency,
            reconciliation_reference=reconciliation_reference or f"rec_{case_id}_{now.strftime('%Y%m%d%H%M%S')}",
            recorded_at=now,
        )

        with self._lock:
            self._entries.append(entry)
            self._record_audit_event(entry, now)

        return entry

    def record_gross_recovery(
        self,
        case_id: str,
        gross_amount: int,
        currency: str = "INR",
        execution_id: Optional[str] = None,
        reference: str = "",
        current_time: Optional[datetime] = None,
    ) -> RevenueLedgerEntry:
        """
        Stage 1: Records an initial successful payment recovery as gross unconfirmed revenue (INV-11).
        Enforces gross_amount > 0 and strictly net_confirmed_amount = 0.
        """
        if gross_amount <= 0:
            raise ValueError(f"Gross recovery amount must be positive, got {gross_amount}")

        return self.record_entry(
            case_id=case_id,
            financial_state=FinancialState.GROSS_RECOVERED,
            gross_amount=gross_amount,
            net_confirmed_amount=0,
            currency=currency,
            execution_id=execution_id,
            reconciliation_reference=reference,
            current_time=current_time,
        )

    def record_confirmed_settlement(
        self,
        case_id: str,
        gross_amount: int,
        net_confirmed_amount: int,
        currency: str = "INR",
        execution_id: Optional[str] = None,
        settlement_reference: str = "",
        current_time: Optional[datetime] = None,
    ) -> RevenueLedgerEntry:
        """
        Stage 2: Records verified settlement reconciliation as confirmed revenue (INV-11).
        Enforces 0 < net_confirmed_amount <= gross_amount.
        """
        if gross_amount <= 0:
            raise ValueError(f"gross_amount must be positive, got {gross_amount}")
        if net_confirmed_amount <= 0:
            raise ValueError(f"net_confirmed_amount must be positive, got {net_confirmed_amount}")
        if net_confirmed_amount > gross_amount:
            raise ValueError(
                f"net_confirmed_amount ({net_confirmed_amount}) cannot exceed gross_amount ({gross_amount})"
            )

        return self.record_entry(
            case_id=case_id,
            financial_state=FinancialState.CONFIRMED_SETTLED,
            gross_amount=gross_amount,
            net_confirmed_amount=net_confirmed_amount,
            currency=currency,
            execution_id=execution_id,
            reconciliation_reference=settlement_reference,
            current_time=current_time,
        )

    def get_entries_for_case(self, case_id: str) -> tuple[RevenueLedgerEntry, ...]:
        """
        Deterministically queries all immutable ledger entries for a given case_id in chronological order.
        """
        with self._lock:
            matching = [e for e in self._entries if e.case_id == case_id]
            matching.sort(key=lambda e: (e.recorded_at, e.entry_id))
            return tuple(matching)

    def get_case_summary(self, case_id: str, current_time: Optional[datetime] = None) -> LedgerSummary:
        """
        Computes aggregated financial summary for a case.
        Strictly distinguishes total gross recovered from total net confirmed settled revenue (INV-11).
        """
        now = current_time or datetime.now(timezone.utc)
        with self._lock:
            entries = self.get_entries_for_case(case_id)
            if not entries:
                raise ValueError(f"No ledger entries found for case_id '{case_id}'")

            currency = entries[0].currency
            latest_entry = entries[-1]

            # In two-stage accounting:
            # - total_gross_recovered: highest gross recorded among recovery stages
            # - total_net_confirmed: latest confirmed settled amount if in confirmed state, else 0
            gross_max = max(
                (
                    e.gross_amount
                    for e in entries
                    if e.financial_state
                    in {
                        FinancialState.GROSS_RECOVERED.value,
                        FinancialState.CONFIRMED_SETTLED.value,
                    }
                ),
                default=0,
            )

            # Confirmed revenue is only recognized when CONFIRMED_SETTLED entry exists
            confirmed_entries = [e for e in entries if e.financial_state == FinancialState.CONFIRMED_SETTLED.value]
            net_confirmed = confirmed_entries[-1].net_confirmed_amount if confirmed_entries else 0

            # If disputed/refunded/written_off, confirmed revenue is not recognized
            if latest_entry.financial_state in {
                FinancialState.DISPUTED.value,
                FinancialState.REFUNDED.value,
                FinancialState.WRITTEN_OFF.value,
            }:
                net_confirmed = 0

            return LedgerSummary(
                case_id=case_id,
                currency=currency,
                total_gross_recovered=gross_max,
                total_net_confirmed=net_confirmed,
                latest_state=latest_entry.financial_state,
                entry_count=len(entries),
                computed_at=now,
            )

    def get_all_entries(self) -> tuple[RevenueLedgerEntry, ...]:
        """Deterministically queries all ledger entries across the system for auditing."""
        with self._lock:
            sorted_entries = list(self._entries)
            sorted_entries.sort(key=lambda e: (e.recorded_at, e.entry_id))
            return tuple(sorted_entries)

    def _record_audit_event(self, entry: RevenueLedgerEntry, now: datetime) -> None:
        """Emits LEDGER_ENTRY_RECORDED event to CryptographicAuditLogger if present (INV-18)."""
        if self.audit_logger is not None:
            state_str = (
                entry.financial_state.value
                if isinstance(entry.financial_state, FinancialState)
                else str(entry.financial_state)
            )
            event = LedgerEntryRecordedEvent(
                entry_id=entry.entry_id,
                case_id=entry.case_id,
                financial_state=state_str,
                gross_amount=entry.gross_amount,
                net_confirmed_amount=entry.net_confirmed_amount,
                currency=entry.currency,
                reconciliation_reference=entry.reconciliation_reference,
                occurred_at=now,
            )
            self.audit_logger.append(
                event_type="LEDGER_ENTRY_RECORDED",
                payload=event.model_dump(mode="json"),
                timestamp=now,
            )
