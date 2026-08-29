"""Unit tests for fail-closed global and granular Kill Switch (TICKET-06).

Architecture Baseline: Frozen Architecture Baseline v11.
Proves fail-closed execution halting across global and granular scopes.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from src.revenue_recovery.foundation.events import ActionChannel, ActionType
from src.revenue_recovery.safety import (
    KillSwitchActiveError,
    KillSwitchManager,
    KillSwitchRecord,
    KillSwitchScope,
)


class TestKillSwitchRecord:
    """Tests for KillSwitchRecord immutability and schema."""

    def test_record_creation_and_immutability(self):
        record = KillSwitchRecord(
            scope=KillSwitchScope.GLOBAL,
            target="GLOBAL",
            reason="Emergency maintenance",
            activated_by="operator_001"
        )
        assert record.scope == KillSwitchScope.GLOBAL
        assert record.target == "GLOBAL"
        assert record.reason == "Emergency maintenance"
        assert record.activated_by == "operator_001"
        assert isinstance(record.activated_at, datetime)

        with pytest.raises(ValidationError):
            record.reason = "Tampered reason"  # type: ignore


class TestKillSwitchManager:
    """Tests for KillSwitchManager activation, deactivation, and fail-closed checks."""

    @pytest.fixture
    def ks(self) -> KillSwitchManager:
        return KillSwitchManager()

    def test_initially_inactive(self, ks: KillSwitchManager):
        assert ks.is_global_active() is False
        assert ks.is_active() is False
        assert ks.check_execution_allowed() is True

    def test_global_kill_switch_lifecycle(self, ks: KillSwitchManager):
        # 1. Activate global
        rec = ks.activate_global(reason="High error rate detected", activated_by="ops_lead")
        assert rec.scope == KillSwitchScope.GLOBAL
        assert ks.is_global_active() is True
        assert ks.is_active() is True

        # Any check fails closed
        with pytest.raises(KillSwitchActiveError) as exc_info:
            ks.check_execution_allowed(
                action_type=ActionType.RETRY_CHARGE,
                channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
                customer_id="cust_1",
                case_id="case_1"
            )
        assert exc_info.value.scope == KillSwitchScope.GLOBAL
        assert exc_info.value.reason == "High error rate detected"

        # 2. Deactivate global
        deactivated = ks.deactivate_global()
        assert deactivated is True
        assert ks.is_global_active() is False
        assert ks.check_execution_allowed() is True

    def test_action_type_granular_kill_switch(self, ks: KillSwitchManager):
        ks.activate_action_type(ActionType.RETRY_CHARGE, reason="Gateway outage", activated_by="auto_guard")

        # RETRY_CHARGE is blocked
        assert ks.is_active(action_type=ActionType.RETRY_CHARGE) is True
        with pytest.raises(KillSwitchActiveError) as exc_info:
            ks.check_execution_allowed(action_type=ActionType.RETRY_CHARGE)
        assert exc_info.value.scope == KillSwitchScope.ACTION_TYPE
        assert exc_info.value.target == "RETRY_CHARGE"

        # Other action types remain permitted
        assert ks.is_active(action_type=ActionType.SEND_NOTIFICATION) is False
        assert ks.check_execution_allowed(action_type=ActionType.SEND_NOTIFICATION) is True

        # Deactivate
        ks.deactivate_action_type(ActionType.RETRY_CHARGE)
        assert ks.is_active(action_type=ActionType.RETRY_CHARGE) is False
        assert ks.check_execution_allowed(action_type=ActionType.RETRY_CHARGE) is True

    def test_channel_granular_kill_switch(self, ks: KillSwitchManager):
        ks.activate_channel(ActionChannel.SMS, reason="SMS provider degradation", activated_by="ops_lead")

        # SMS is blocked
        assert ks.is_active(channel=ActionChannel.SMS) is True
        with pytest.raises(KillSwitchActiveError) as exc_info:
            ks.check_execution_allowed(channel=ActionChannel.SMS)
        assert exc_info.value.scope == KillSwitchScope.ACTION_CHANNEL
        assert exc_info.value.target == "SMS"

        # Other channels are permitted
        assert ks.is_active(channel=ActionChannel.EMAIL) is False
        assert ks.check_execution_allowed(channel=ActionChannel.EMAIL) is True
        assert ks.check_execution_allowed(channel=ActionChannel.DIRECT_PAYMENT_GATEWAY) is True

        # Deactivate
        ks.deactivate_channel(ActionChannel.SMS)
        assert ks.is_active(channel=ActionChannel.SMS) is False
        assert ks.check_execution_allowed(channel=ActionChannel.SMS) is True

    def test_customer_granular_kill_switch(self, ks: KillSwitchManager):
        ks.activate_customer("cust_vip_frozen", reason="Customer requested temporary hold", activated_by="support_rep")

        # Specific customer blocked
        assert ks.is_active(customer_id="cust_vip_frozen") is True
        with pytest.raises(KillSwitchActiveError) as exc_info:
            ks.check_execution_allowed(customer_id="cust_vip_frozen")
        assert exc_info.value.scope == KillSwitchScope.CUSTOMER
        assert exc_info.value.target == "cust_vip_frozen"

        # Other customers permitted
        assert ks.is_active(customer_id="cust_other") is False
        assert ks.check_execution_allowed(customer_id="cust_other") is True

        # Deactivate
        ks.deactivate_customer("cust_vip_frozen")
        assert ks.is_active(customer_id="cust_vip_frozen") is False
        assert ks.check_execution_allowed(customer_id="cust_vip_frozen") is True

    def test_case_granular_kill_switch(self, ks: KillSwitchManager):
        ks.activate_case("case_dispute_123", reason="Dispute opened", activated_by="compliance_officer")

        # Specific case blocked
        assert ks.is_active(case_id="case_dispute_123") is True
        with pytest.raises(KillSwitchActiveError) as exc_info:
            ks.check_execution_allowed(case_id="case_dispute_123")
        assert exc_info.value.scope == KillSwitchScope.CASE
        assert exc_info.value.target == "case_dispute_123"

        # Other cases permitted
        assert ks.is_active(case_id="case_normal_456") is False
        assert ks.check_execution_allowed(case_id="case_normal_456") is True

        # Deactivate
        ks.deactivate_case("case_dispute_123")
        assert ks.is_active(case_id="case_dispute_123") is False
        assert ks.check_execution_allowed(case_id="case_dispute_123") is True

    def test_global_scope_precedence_over_granular(self, ks: KillSwitchManager):
        ks.activate_channel(ActionChannel.DIRECT_PAYMENT_GATEWAY, reason="Gateway issue")
        ks.activate_global(reason="Platform-wide shutdown")

        # Global record is returned first
        rec = ks.get_active_switch_record(channel=ActionChannel.DIRECT_PAYMENT_GATEWAY)
        assert rec is not None
        assert rec.scope == KillSwitchScope.GLOBAL

    def test_reset_all_clears_all_switches(self, ks: KillSwitchManager):
        ks.activate_global("Global halt")
        ks.activate_action_type(ActionType.RETRY_CHARGE, "Halt retry")
        ks.activate_channel(ActionChannel.SMS, "Halt SMS")
        ks.activate_customer("cust_1", "Halt cust 1")
        ks.activate_case("case_1", "Halt case 1")

        assert ks.is_active() is True
        ks.reset_all()

        assert ks.is_global_active() is False
        assert ks.is_active(
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.SMS,
            customer_id="cust_1",
            case_id="case_1"
        ) is False
        assert ks.check_execution_allowed() is True

    def test_concurrent_activations_and_checks(self, ks: KillSwitchManager):
        """Proves thread-safety across concurrent activations, deactivations, and checks."""
        errors: list[Exception] = []

        def worker(worker_id: int):
            try:
                for i in range(25):
                    cust_id = f"cust_worker_{worker_id}_{i}"
                    case_id = f"case_worker_{worker_id}_{i}"
                    ks.activate_customer(cust_id, "Concurrency test")
                    assert ks.is_active(customer_id=cust_id) is True
                    ks.deactivate_customer(cust_id)
                    assert ks.is_active(customer_id=cust_id) is False
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(worker, w) for w in range(8)]
            for f in futures:
                f.result()

        assert len(errors) == 0

    def test_public_safety_exports_include_kill_switch(self):
        import src.revenue_recovery.safety as safety
        assert hasattr(safety, "KillSwitchActiveError")
        assert hasattr(safety, "KillSwitchManager")
        assert hasattr(safety, "KillSwitchRecord")
        assert hasattr(safety, "KillSwitchScope")
