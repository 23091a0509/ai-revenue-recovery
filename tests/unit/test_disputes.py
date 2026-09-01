"""Dispute & Chargeback Financial Tracking Invariant Tests (INV-12 / TICKET-24).

Authoritative Basis:
- Frozen Architecture Baseline v11 Requirements.
- INV-11: Gross recovered != Confirmed recovered.
- INV-12: Dispute & chargeback financial tracking (Dispute webhooks adjust net confirmed revenue to negative/loss).
- INV-18: Complete audit logging of financial transitions via append-only cryptographic logger.
"""

from datetime import datetime, timezone
import pytest

from src.revenue_recovery.foundation.audit import CryptographicAuditLogger
from src.revenue_recovery.reconciliation import (
    DisputeReason,
    DisputeStage,
    DisputeWebhook,
    FinancialState,
    RevenueLedger,
    SettlementDisputeHandler,
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


class TestDisputeFinancialTrackingInvariant:
    """Verifies INV-12: Dispute & chargeback tracking nullifies confirmed revenue."""

    def test_full_recovery_to_dispute_lifecycle_loss_tracking(
        self, handler: SettlementDisputeHandler, ledger: RevenueLedger
    ):
        case_id = "case_lifecycle_inv12_001"
        t0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2026, 9, 1, 10, 5, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 9, 1, 11, 0, 0, tzinfo=timezone.utc)
        t3 = datetime(2026, 9, 1, 15, 0, 0, tzinfo=timezone.utc)

        # 1. Initiated & Gross recovery (Stage 1)
        ledger.record_gross_recovery(case_id=case_id, gross_amount=50000, current_time=t0)
        s1 = ledger.get_case_summary(case_id)
        assert s1.total_gross_recovered == 50000
        assert s1.total_net_confirmed == 0
        assert s1.latest_state == FinancialState.GROSS_RECOVERED

        # 2. Settlement Confirmed (Stage 2)
        set_wb = SettlementWebhook(
            event_id="evt_set_inv12_01",
            settlement_id="set_inv12_01",
            case_id=case_id,
            gross_amount=50000,
            fee_amount=1500,
            net_amount=48500,
            currency="INR",
            settled_at=t1,
        )
        handler.process_settlement(set_wb)
        s2 = ledger.get_case_summary(case_id)
        assert s2.total_gross_recovered == 50000
        assert s2.total_net_confirmed == 48500
        assert s2.latest_state == FinancialState.CONFIRMED_SETTLED

        # 3. Dispute Opened (INV-12: Net confirmed nullified)
        disp_wb = DisputeWebhook(
            event_id="evt_disp_inv12_01",
            dispute_id="dp_inv12_01",
            case_id=case_id,
            disputed_amount=50000,
            fee_amount=2000,
            currency="INR",
            reason=DisputeReason.FRAUDULENT,
            stage=DisputeStage.NEEDS_RESPONSE,
            occurred_at=t2,
        )
        handler.process_dispute(disp_wb)
        s3 = ledger.get_case_summary(case_id)
        assert s3.total_net_confirmed == 0
        assert s3.latest_state == FinancialState.DISPUTED

        # 4. Dispute Lost (INV-12: Loss confirmed as WRITTEN_OFF)
        disp_lost_wb = DisputeWebhook(
            event_id="evt_disp_inv12_02",
            dispute_id="dp_inv12_01",
            case_id=case_id,
            disputed_amount=50000,
            fee_amount=2000,
            currency="INR",
            reason=DisputeReason.FRAUDULENT,
            stage=DisputeStage.LOST,
            occurred_at=t3,
        )
        handler.process_dispute(disp_lost_wb)
        s4 = ledger.get_case_summary(case_id)
        assert s4.total_net_confirmed == 0
        assert s4.latest_state == FinancialState.WRITTEN_OFF
        assert s4.entry_count == 4
