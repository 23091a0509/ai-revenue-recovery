"""Unit and Invariant Tests for Settlement and Dispute Reconciliation Engine (TICKET-24).

Authoritative Basis:
- Frozen Architecture Baseline v11 Requirements.
- INV-01: AI recommends; it does not execute.
- INV-02: Least-privilege authority boundaries (zero execution/token-minting authority).
- INV-11: Gross recovered != Confirmed recovered (Two-stage revenue ledger requiring settlement reconciliation).
- INV-12: Dispute & chargeback financial tracking (Dispute webhooks adjust net confirmed revenue to negative/loss).
- INV-18: Complete audit logging of financial transitions via append-only cryptographic logger.

Test Scope:
1. DisputeReason and DisputeStage enum verification.
2. SettlementWebhook and DisputeWebhook model validation.
3. Settlement reconciliation math (net_amount = gross_amount - fee_amount).
4. Confirmed settlement recording into RevenueLedger.
5. Settlement webhook idempotency.
6. Dispute processing across stages (NEEDS_RESPONSE, UNDER_REVIEW, LOST, WON).
7. Dispute idempotency and fee tracking.
8. Refund processing.
9. Append-only preservation of the underlying ledger.
10. Cryptographic audit trail generation and unbroken hash chains (INV-18).
11. Thread-safe webhook deduplication.
12. Authority boundary isolation.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from src.revenue_recovery.foundation.audit import CryptographicAuditLogger
from src.revenue_recovery.reconciliation import (
    DisputeReason,
    DisputeReconciledEvent,
    DisputeStage,
    DisputeWebhook,
    FinancialState,
    RevenueLedger,
    RevenueLedgerEntry,
    SettlementDisputeHandler,
    SettlementReconciledEvent,
    SettlementWebhook,
)


@pytest.fixture
def audit_logger() -> CryptographicAuditLogger:
    return CryptographicAuditLogger()


@pytest.fixture
def ledger(audit_logger: CryptographicAuditLogger) -> RevenueLedger:
    return RevenueLedger(audit_logger=audit_logger)


@pytest.fixture
def handler(ledger: RevenueLedger, audit_logger: CryptographicAuditLogger) -> SettlementDisputeHandler:
    return SettlementDisputeHandler(ledger=ledger, audit_logger=audit_logger)


# ============================================================================
# PART 1: Enums & Model Validations
# ============================================================================

class TestDisputeModelsAndEnums:
    """Verifies enum values and webhook validation constraints."""

    def test_dispute_reason_enum_values(self):
        expected = {
            "FRAUDULENT",
            "UNRECOGNIZED_CHARGE",
            "PRODUCT_NOT_RECEIVED",
            "DUPLICATE_CHARGE",
            "SUBSCRIPTION_CANCELED",
            "GENERAL",
        }
        actual = {r.value for r in DisputeReason}
        assert actual == expected

    def test_dispute_stage_enum_values(self):
        expected = {"NEEDS_RESPONSE", "UNDER_REVIEW", "LOST", "WON"}
        actual = {s.value for s in DisputeStage}
        assert actual == expected

    def test_settlement_webhook_gross_minus_fee_validation(self):
        # Valid settlement
        wb = SettlementWebhook(
            event_id="evt_set_001",
            settlement_id="set_001",
            case_id="case_001",
            gross_amount=10000,
            fee_amount=300,
            net_amount=9700,
            currency="INR",
        )
        assert wb.net_amount == 9700

        # Inconsistent net amount fails
        with pytest.raises(ValidationError, match="net_amount"):
            SettlementWebhook(
                event_id="evt_set_002",
                settlement_id="set_002",
                case_id="case_001",
                gross_amount=10000,
                fee_amount=300,
                net_amount=9500,  # Wrong: 10000 - 300 = 9700
                currency="INR",
            )

    def test_dispute_webhook_validation(self):
        wb = DisputeWebhook(
            event_id="evt_disp_001",
            dispute_id="dp_001",
            case_id="case_001",
            disputed_amount=10000,
            fee_amount=1500,
            currency="USD",
            reason=DisputeReason.FRAUDULENT,
            stage=DisputeStage.NEEDS_RESPONSE,
        )
        assert wb.currency == "USD"
        assert wb.fee_amount == 1500


# ============================================================================
# PART 2: Settlement Reconciliation (INV-11)
# ============================================================================

class TestSettlementReconciliation:
    """Verifies gateway settlement payout processing and idempotency."""

    def test_process_settlement_creates_confirmed_settled_entry(
        self, handler: SettlementDisputeHandler, ledger: RevenueLedger
    ):
        case_id = "case_set_test_001"
        # Initial gross recovery recorded
        ledger.record_gross_recovery(case_id=case_id, gross_amount=20000)

        webhook = SettlementWebhook(
            event_id="evt_set_101",
            settlement_id="set_101",
            case_id=case_id,
            gross_amount=20000,
            fee_amount=600,
            net_amount=19400,
            currency="INR",
        )

        entry = handler.process_settlement(webhook)
        assert entry.financial_state == FinancialState.CONFIRMED_SETTLED
        assert entry.gross_amount == 20000
        assert entry.net_confirmed_amount == 19400

        # Verify summary reflects confirmed settlement
        summary = ledger.get_case_summary(case_id)
        assert summary.total_gross_recovered == 20000
        assert summary.total_net_confirmed == 19400
        assert summary.latest_state == FinancialState.CONFIRMED_SETTLED

    def test_settlement_webhook_idempotency(
        self, handler: SettlementDisputeHandler, ledger: RevenueLedger
    ):
        case_id = "case_set_idem_001"
        webhook = SettlementWebhook(
            event_id="evt_set_duplicate",
            settlement_id="set_dup_101",
            case_id=case_id,
            gross_amount=15000,
            fee_amount=450,
            net_amount=14550,
            currency="INR",
        )

        entry1 = handler.process_settlement(webhook)
        entry2 = handler.process_settlement(webhook)

        # Must return the same ledger entry without appending duplicate rows
        assert entry1.entry_id == entry2.entry_id
        entries = ledger.get_entries_for_case(case_id)
        assert len(entries) == 1


# ============================================================================
# PART 3: Dispute Reconciliation (INV-12)
# ============================================================================

class TestDisputeReconciliation:
    """Verifies chargeback/dispute lifecycle processing and loss tracking."""

    def test_process_dispute_transitions_state_and_adjusts_confirmed_revenue(
        self, handler: SettlementDisputeHandler, ledger: RevenueLedger
    ):
        case_id = "case_disp_test_001"
        # Stage 1 & 2: Recovered and settled
        ledger.record_gross_recovery(case_id=case_id, gross_amount=25000)
        ledger.record_confirmed_settlement(
            case_id=case_id, gross_amount=25000, net_confirmed_amount=24250
        )

        # Stage 3: Dispute arrives (NEEDS_RESPONSE)
        webhook = DisputeWebhook(
            event_id="evt_disp_101",
            dispute_id="dp_101",
            case_id=case_id,
            disputed_amount=25000,
            fee_amount=1500,
            currency="INR",
            reason=DisputeReason.FRAUDULENT,
            stage=DisputeStage.NEEDS_RESPONSE,
        )

        entry = handler.process_dispute(webhook)
        assert entry.financial_state == FinancialState.DISPUTED
        assert entry.net_confirmed_amount == 0

        # Confirmed revenue is now nullified in summary
        summary = ledger.get_case_summary(case_id)
        assert summary.latest_state == FinancialState.DISPUTED
        assert summary.total_net_confirmed == 0

    def test_lost_dispute_records_written_off(
        self, handler: SettlementDisputeHandler, ledger: RevenueLedger
    ):
        case_id = "case_disp_lost_001"
        webhook = DisputeWebhook(
            event_id="evt_disp_lost_101",
            dispute_id="dp_lost_101",
            case_id=case_id,
            disputed_amount=30000,
            fee_amount=2000,
            currency="INR",
            reason=DisputeReason.UNRECOGNIZED_CHARGE,
            stage=DisputeStage.LOST,
        )

        entry = handler.process_dispute(webhook)
        assert entry.financial_state == FinancialState.WRITTEN_OFF
        assert entry.net_confirmed_amount == 0

    def test_won_dispute_restores_confirmed_settled(
        self, handler: SettlementDisputeHandler, ledger: RevenueLedger
    ):
        case_id = "case_disp_won_001"
        webhook = DisputeWebhook(
            event_id="evt_disp_won_101",
            dispute_id="dp_won_101",
            case_id=case_id,
            disputed_amount=30000,
            fee_amount=0,
            currency="INR",
            reason=DisputeReason.PRODUCT_NOT_RECEIVED,
            stage=DisputeStage.WON,
        )

        entry = handler.process_dispute(webhook)
        assert entry.financial_state == FinancialState.CONFIRMED_SETTLED
        assert entry.net_confirmed_amount == 30000

    def test_dispute_webhook_idempotency(
        self, handler: SettlementDisputeHandler, ledger: RevenueLedger
    ):
        case_id = "case_disp_idem_001"
        webhook = DisputeWebhook(
            event_id="evt_disp_dup_101",
            dispute_id="dp_dup_101",
            case_id=case_id,
            disputed_amount=20000,
            currency="INR",
            reason=DisputeReason.DUPLICATE_CHARGE,
            stage=DisputeStage.UNDER_REVIEW,
        )

        entry1 = handler.process_dispute(webhook)
        entry2 = handler.process_dispute(webhook)

        assert entry1.entry_id == entry2.entry_id
        assert len(ledger.get_entries_for_case(case_id)) == 1


# ============================================================================
# PART 4: Refunds & Audit Trail (INV-18)
# ============================================================================

class TestRefundsAndAuditTrail:
    """Verifies refund handling and cryptographic audit event verification."""

    def test_process_refund_appends_refunded_entry(
        self, handler: SettlementDisputeHandler, ledger: RevenueLedger
    ):
        case_id = "case_ref_001"
        entry = handler.process_refund(
            case_id=case_id,
            refund_amount=10000,
            currency="INR",
            reference="ref_user_cancel_001",
        )
        assert entry.financial_state == FinancialState.REFUNDED
        assert entry.gross_amount == 10000
        assert entry.net_confirmed_amount == 0

    def test_settlement_and_dispute_audit_events_preserve_chain(
        self, handler: SettlementDisputeHandler, audit_logger: CryptographicAuditLogger
    ):
        set_wb = SettlementWebhook(
            event_id="evt_audit_set_001",
            settlement_id="set_aud_001",
            case_id="case_aud_001",
            gross_amount=12000,
            fee_amount=360,
            net_amount=11640,
            currency="INR",
        )
        handler.process_settlement(set_wb)

        disp_wb = DisputeWebhook(
            event_id="evt_audit_disp_001",
            dispute_id="dp_aud_001",
            case_id="case_aud_001",
            disputed_amount=12000,
            fee_amount=1500,
            currency="INR",
            reason=DisputeReason.GENERAL,
            stage=DisputeStage.NEEDS_RESPONSE,
        )
        handler.process_dispute(disp_wb)

        event_types = [e.event_type for e in audit_logger.entries]
        assert "SETTLEMENT_RECONCILED" in event_types
        assert "DISPUTE_RECONCILED" in event_types
        assert audit_logger.verify_chain_integrity() is True


# ============================================================================
# PART 5: Concurrency & Authority Boundaries (INV-01, INV-02)
# ============================================================================

class TestHandlerConcurrencyAndAuthorityBoundaries:
    """Verifies thread safety and strict authority isolation."""

    def test_concurrent_settlement_and_dispute_webhooks_thread_safe(
        self, handler: SettlementDisputeHandler, ledger: RevenueLedger
    ):
        num_threads = 8
        items_per_thread = 15

        def worker(t_idx: int):
            for i in range(items_per_thread):
                wb = SettlementWebhook(
                    event_id=f"evt_conc_{t_idx}_{i}",
                    settlement_id=f"set_conc_{t_idx}_{i}",
                    case_id=f"case_conc_{t_idx}",
                    gross_amount=1000 + i,
                    fee_amount=30,
                    net_amount=970 + i,
                    currency="INR",
                )
                handler.process_settlement(wb)

        with ThreadPoolExecutor(max_workers=num_threads) as pool:
            futures = [pool.submit(worker, idx) for idx in range(num_threads)]
            for f in futures:
                f.result()

        all_entries = ledger.get_all_entries()
        assert len(all_entries) == num_threads * items_per_thread

    def test_handler_has_no_execution_or_token_minting_capabilities(
        self, handler: SettlementDisputeHandler
    ):
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
        for m in forbidden_methods:
            assert not hasattr(handler, m), f"SettlementDisputeHandler must not expose '{m}'"
