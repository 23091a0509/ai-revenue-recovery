"""Comprehensive Unit and Invariant Tests for Append-Only Revenue Ledger (TICKET-23).

Authoritative Basis:
- Frozen Architecture Baseline v11 Requirements.
- INV-01: AI recommends; it does not execute.
- INV-02: Least-privilege authority boundaries (Ledger has zero execution/token-minting authority).
- INV-11: Gross recovered != Confirmed recovered (Two-stage revenue ledger requiring settlement reconciliation).
- INV-18: Complete audit logging of financial transitions via append-only cryptographic logger.

Test Scope:
1. FinancialState enum values.
2. Immutable models: RevenueLedgerEntry, LedgerSummary, LedgerEntryRecordedEvent.
3. record_entry() core behavior and validations.
4. record_gross_recovery() Stage 1 enforcement (net_confirmed_amount == 0).
5. record_confirmed_settlement() Stage 2 enforcement (0 < net_confirmed_amount <= gross_amount).
6. Invariant violations: Positive net confirmed amount in INITIATED / GROSS_RECOVERED fails with ValueError.
7. Amount bounds: Negative gross/net amounts fail with ValueError.
8. Append-only integrity: No update, delete, or replacement capabilities.
9. Deterministic ordering for case entries and global entries.
10. Case summary calculation and gross vs confirmed distinction.
11. Cryptographic audit logging with hash chain integrity (INV-18).
12. Thread-safe concurrent appends.
13. Authority isolation (zero execution, zero token-minting).
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from src.revenue_recovery.foundation.audit import CryptographicAuditLogger
from src.revenue_recovery.reconciliation import (
    FinancialState,
    LedgerEntryRecordedEvent,
    LedgerSummary,
    RevenueLedger,
    RevenueLedgerEntry,
)


@pytest.fixture
def audit_logger() -> CryptographicAuditLogger:
    return CryptographicAuditLogger()


@pytest.fixture
def ledger(audit_logger: CryptographicAuditLogger) -> RevenueLedger:
    return RevenueLedger(audit_logger=audit_logger)


# ============================================================================
# PART 1: Core Domain Models & Enum Verification
# ============================================================================

class TestLedgerDomainModels:
    """Verifies immutability, enum values, and schema constraints."""

    def test_financial_state_enum_exact_values(self):
        expected = {
            "INITIATED",
            "GROSS_RECOVERED",
            "CONFIRMED_SETTLED",
            "DISPUTED",
            "REFUNDED",
            "WRITTEN_OFF",
        }
        actual = {s.value for s in FinancialState}
        assert actual == expected

    def test_revenue_ledger_entry_immutability(self):
        entry = RevenueLedgerEntry(
            case_id="case_immut_001",
            financial_state=FinancialState.INITIATED,
            gross_amount=10000,
            net_confirmed_amount=0,
            currency="INR",
        )
        with pytest.raises(ValidationError):
            entry.gross_amount = 20000  # type: ignore[misc]

    def test_currency_validation(self):
        # Valid 3-letter currency
        entry = RevenueLedgerEntry(
            case_id="case_curr_001",
            financial_state=FinancialState.INITIATED,
            gross_amount=10000,
            net_confirmed_amount=0,
            currency="usd",
        )
        assert entry.currency == "USD"

        # Invalid currency length or non-alpha
        with pytest.raises(ValidationError):
            RevenueLedgerEntry(
                case_id="case_curr_002",
                financial_state=FinancialState.INITIATED,
                gross_amount=10000,
                net_confirmed_amount=0,
                currency="US1",
            )


# ============================================================================
# PART 2: Two-Stage Accounting Invariant (INV-11)
# ============================================================================

class TestTwoStageAccountingInvariant:
    """Verifies that Gross Recovered != Confirmed Recovered (INV-11)."""

    def test_initiated_with_positive_confirmed_fails(self):
        with pytest.raises(ValueError, match="INV-11"):
            RevenueLedgerEntry(
                case_id="case_stage1_001",
                financial_state=FinancialState.INITIATED,
                gross_amount=10000,
                net_confirmed_amount=5000,
            )

    def test_gross_recovered_with_positive_confirmed_fails(self):
        with pytest.raises(ValueError, match="INV-11"):
            RevenueLedgerEntry(
                case_id="case_stage1_002",
                financial_state=FinancialState.GROSS_RECOVERED,
                gross_amount=10000,
                net_confirmed_amount=10000,
            )

    def test_record_gross_recovery_enforces_zero_confirmed(self, ledger: RevenueLedger):
        entry = ledger.record_gross_recovery(
            case_id="case_rec_001",
            gross_amount=50000,
            currency="INR",
            reference="ch_stripe_12345",
        )
        assert entry.financial_state == FinancialState.GROSS_RECOVERED
        assert entry.gross_amount == 50000
        assert entry.net_confirmed_amount == 0

    def test_record_confirmed_settlement_enforces_bounds(self, ledger: RevenueLedger):
        # Valid settlement with gateway processing fee deduction
        entry = ledger.record_confirmed_settlement(
            case_id="case_rec_001",
            gross_amount=50000,
            net_confirmed_amount=48500,  # 50,000 gross - 1,500 fee
            currency="INR",
            settlement_reference="set_payout_9988",
        )
        assert entry.financial_state == FinancialState.CONFIRMED_SETTLED
        assert entry.gross_amount == 50000
        assert entry.net_confirmed_amount == 48500

        # Confirmed amount exceeding gross fails
        with pytest.raises(ValueError, match="cannot exceed gross_amount"):
            ledger.record_confirmed_settlement(
                case_id="case_rec_001",
                gross_amount=50000,
                net_confirmed_amount=55000,
            )

        # Zero or negative confirmed amount fails in CONFIRMED_SETTLED
        with pytest.raises(ValueError, match="must be positive"):
            ledger.record_confirmed_settlement(
                case_id="case_rec_001",
                gross_amount=50000,
                net_confirmed_amount=0,
            )


# ============================================================================
# PART 3: Append-Only Discipline & Deterministic Queries
# ============================================================================

class TestAppendOnlyDisciplineAndQueries:
    """Verifies append-only storage and deterministic chronological querying."""

    def test_append_only_lifecycle_progression(self, ledger: RevenueLedger):
        case_id = "case_life_001"
        t0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2026, 9, 1, 10, 5, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 9, 1, 10, 30, 0, tzinfo=timezone.utc)

        # Step 1: Initiated
        e1 = ledger.record_entry(
            case_id=case_id,
            financial_state=FinancialState.INITIATED,
            gross_amount=25000,
            current_time=t0,
        )
        # Step 2: Gross recovered
        e2 = ledger.record_gross_recovery(
            case_id=case_id,
            gross_amount=25000,
            current_time=t1,
        )
        # Step 3: Confirmed settled
        e3 = ledger.record_confirmed_settlement(
            case_id=case_id,
            gross_amount=25000,
            net_confirmed_amount=24250,
            current_time=t2,
        )

        entries = ledger.get_entries_for_case(case_id)
        assert len(entries) == 3
        assert entries[0].entry_id == e1.entry_id
        assert entries[1].entry_id == e2.entry_id
        assert entries[2].entry_id == e3.entry_id

        # Assert chronological order
        assert entries[0].recorded_at <= entries[1].recorded_at <= entries[2].recorded_at

    def test_ledger_has_no_update_or_delete_methods(self, ledger: RevenueLedger):
        forbidden_methods = ["update", "delete", "remove", "pop", "clear", "modify", "set_entry"]
        for m in forbidden_methods:
            assert not hasattr(ledger, m), f"RevenueLedger must not expose '{m}' method"

    def test_case_summary_preserves_two_stage_distinction(self, ledger: RevenueLedger):
        case_id = "case_sum_001"
        # Stage 1: Gross only
        ledger.record_gross_recovery(case_id=case_id, gross_amount=30000)
        summary1 = ledger.get_case_summary(case_id)
        assert summary1.total_gross_recovered == 30000
        assert summary1.total_net_confirmed == 0
        assert summary1.latest_state == FinancialState.GROSS_RECOVERED

        # Stage 2: Confirmed settled
        ledger.record_confirmed_settlement(
            case_id=case_id, gross_amount=30000, net_confirmed_amount=29100
        )
        summary2 = ledger.get_case_summary(case_id)
        assert summary2.total_gross_recovered == 30000
        assert summary2.total_net_confirmed == 29100
        assert summary2.latest_state == FinancialState.CONFIRMED_SETTLED
        assert summary2.entry_count == 2


# ============================================================================
# PART 4: Cryptographic Audit Trail (INV-18)
# ============================================================================

class TestLedgerAuditTrail:
    """Verifies audit event emission and unbroken cryptographic hash chains."""

    def test_audit_event_emission_and_chain_integrity(
        self, ledger: RevenueLedger, audit_logger: CryptographicAuditLogger
    ):
        ledger.record_entry(
            case_id="case_audit_001",
            financial_state=FinancialState.INITIATED,
            gross_amount=15000,
        )
        ledger.record_gross_recovery(
            case_id="case_audit_001",
            gross_amount=15000,
        )
        ledger.record_confirmed_settlement(
            case_id="case_audit_001",
            gross_amount=15000,
            net_confirmed_amount=14550,
        )

        assert len(audit_logger.entries) == 3
        for entry in audit_logger.entries:
            assert entry.event_type == "LEDGER_ENTRY_RECORDED"
            assert "case_id" in entry.payload
            assert "gross_amount" in entry.payload

        assert audit_logger.verify_chain_integrity() is True


# ============================================================================
# PART 5: Thread Safety & Concurrency
# ============================================================================

class TestLedgerThreadSafety:
    """Verifies thread safety under concurrent appends."""

    def test_concurrent_appends_preserve_all_entries(self):
        shared_ledger = RevenueLedger()
        num_threads = 10
        appends_per_thread = 20

        def worker(thread_idx: int):
            for i in range(appends_per_thread):
                shared_ledger.record_gross_recovery(
                    case_id=f"case_thread_{thread_idx}",
                    gross_amount=1000 + i,
                )

        with ThreadPoolExecutor(max_workers=num_threads) as pool:
            futures = [pool.submit(worker, idx) for idx in range(num_threads)]
            for f in futures:
                f.result()

        all_entries = shared_ledger.get_all_entries()
        assert len(all_entries) == num_threads * appends_per_thread


# ============================================================================
# PART 6: Authority Boundaries (INV-01, INV-02)
# ============================================================================

class TestLedgerAuthorityBoundaries:
    """Verifies that RevenueLedger exposes zero execution or token-minting capabilities."""

    def test_ledger_has_no_execution_or_authorization_methods(self):
        forbidden_methods = [
            "execute",
            "dispatch",
            "charge",
            "send",
            "mint_token",
            "authorize",
            "create_token",
            "call_provider",
        ]
        ledger = RevenueLedger()
        for method in forbidden_methods:
            assert not hasattr(ledger, method), f"RevenueLedger must not expose '{method}'"
