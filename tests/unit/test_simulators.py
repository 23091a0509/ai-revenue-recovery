"""Unit tests for Mock Payment and Messaging Simulators (TICKET-11).

Architecture Baseline: Frozen Architecture Baseline v11.
Enforces:
- Spec §7.2: Dedicated local mock endpoints simulating 200 Success, 402 Insufficient Funds,
  504 Gateway Timeout, Card Expired, and multi-channel messaging deliveries.
- Strict sandbox-only isolation with zero external network connectivity.
"""

from datetime import datetime, timedelta, timezone
import pytest

from src.revenue_recovery.foundation.audit import CryptographicAuditLogger
from src.revenue_recovery.foundation.events import (
    ActionChannel,
    ActionType,
    ExecutionStatus,
    FailureReason,
)
from src.revenue_recovery.safety import (
    CapacityGovernor,
    CryptographicAuthorizer,
    GranularCircuitBreakerRegistry,
    KillSwitchManager,
)
from src.revenue_recovery.executor import (
    ActionExecutor,
    ExecutionRequest,
    MockMessagingSimulator,
    MockPaymentSimulator,
    SandboxGuard,
    SandboxViolationError,
    create_sandbox_action_handler,
)


@pytest.fixture
def sandbox_guard() -> SandboxGuard:
    return SandboxGuard(dns_resolver=lambda host, port: ["127.0.0.1"])


@pytest.fixture
def payment_simulator(sandbox_guard: SandboxGuard) -> MockPaymentSimulator:
    return MockPaymentSimulator(sandbox_guard=sandbox_guard)


@pytest.fixture
def messaging_simulator(sandbox_guard: SandboxGuard) -> MockMessagingSimulator:
    return MockMessagingSimulator(sandbox_guard=sandbox_guard)


class TestMockPaymentSimulator:
    """Verifies all payment simulation outcomes, failure modes, and sandbox isolation."""

    def test_payment_success_scenario(self, payment_simulator: MockPaymentSimulator):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        res = payment_simulator.simulate_charge(
            destination_url="http://localhost:8001/charge",
            amount_in_cents=15000,
            currency="INR",
            invoice_id="inv_success_1",
            customer_id="cust_100",
            current_time=t0,
        )

        assert res["status"] == "SUCCESS"
        assert res["http_status"] == 200
        assert res["charge_id"].startswith("ch_mock_")
        assert res["amount_in_cents"] == 15000
        assert res["currency"] == "INR"
        assert res["paid"] is True

        assert len(payment_simulator.history) == 1
        history_item = payment_simulator.history[0]
        assert history_item.status == ExecutionStatus.SUCCESS
        assert history_item.charge_id == res["charge_id"]

    def test_payment_insufficient_funds_failure(self, payment_simulator: MockPaymentSimulator):
        payment_simulator.set_scenario_override("inv_nsf_1", "INSUFFICIENT_FUNDS")
        res = payment_simulator.simulate_charge(
            destination_url="http://localhost:8001/charge",
            amount_in_cents=5000,
            invoice_id="inv_nsf_1",
        )

        assert res["status"] == "FAILED"
        assert res["http_status"] == 402
        assert res["failure_code"] == FailureReason.INSUFFICIENT_FUNDS.value
        assert "insufficient_funds" in res["error"]

    def test_payment_card_expired_failure(self, payment_simulator: MockPaymentSimulator):
        payment_simulator.set_scenario_override("inv_exp_1", "CARD_EXPIRED")
        res = payment_simulator.simulate_charge(
            destination_url="http://localhost:8001/charge",
            amount_in_cents=5000,
            invoice_id="inv_exp_1",
        )

        assert res["status"] == "FAILED"
        assert res["http_status"] == 402
        assert res["failure_code"] == FailureReason.CARD_EXPIRED.value
        assert "expired" in res["error"]

    def test_payment_gateway_timeout_failure(self, payment_simulator: MockPaymentSimulator):
        payment_simulator.set_scenario_override("inv_timeout_1", "GATEWAY_TIMEOUT")
        res = payment_simulator.simulate_charge(
            destination_url="http://localhost:8001/charge",
            amount_in_cents=5000,
            invoice_id="inv_timeout_1",
        )

        assert res["status"] == "FAILED"
        assert res["http_status"] == 504
        assert res["failure_code"] == FailureReason.GATEWAY_TIMEOUT.value

    def test_payment_generic_decline(self, payment_simulator: MockPaymentSimulator):
        payment_simulator.set_scenario_override("inv_declined_1", "DO_NOT_HONOR")
        res = payment_simulator.simulate_charge(
            destination_url="http://localhost:8001/charge",
            amount_in_cents=5000,
            invoice_id="inv_declined_1",
        )

        assert res["status"] == "FAILED"
        assert res["http_status"] == 400
        assert res["failure_code"] == FailureReason.GENERIC_DECLINE.value

    def test_payment_simulator_blocks_production_egress(self, payment_simulator: MockPaymentSimulator):
        with pytest.raises(SandboxViolationError, match="Production egress blocked"):
            payment_simulator.simulate_charge(
                destination_url="https://api.stripe.com/v1/charges",
                amount_in_cents=5000,
                invoice_id="inv_evil_1",
            )


class TestMockMessagingSimulator:
    """Verifies all messaging channels, delivery outcomes, and sandbox isolation."""

    @pytest.mark.parametrize("channel", [ActionChannel.EMAIL, ActionChannel.SMS, ActionChannel.WHATSAPP])
    def test_messaging_success_across_channels(
        self,
        messaging_simulator: MockMessagingSimulator,
        channel: ActionChannel,
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        res = messaging_simulator.simulate_dispatch(
            channel=channel,
            destination_url="http://localhost:8002/messages",
            recipient="user@sandbox.internal",
            message_body="Your subscription payment requires attention.",
            template_id="tpl_recovery_notice_v1",
            current_time=t0,
        )

        assert res["status"] == "SUCCESS"
        assert res["http_status"] == 200
        assert res["message_id"].startswith("msg_mock_")
        assert res["channel"] == str(channel)
        assert res["delivery_status"] == "DELIVERED"
        assert res["template_id"] == "tpl_recovery_notice_v1"

        assert len(messaging_simulator.history) >= 1

    def test_messaging_rate_limited_failure(self, messaging_simulator: MockMessagingSimulator):
        messaging_simulator.set_scenario_override("user_ratelimited@sandbox.internal", "RATE_LIMITED")
        res = messaging_simulator.simulate_dispatch(
            channel=ActionChannel.EMAIL,
            destination_url="http://localhost:8002/messages",
            recipient="user_ratelimited@sandbox.internal",
            message_body="Notice",
        )

        assert res["status"] == "FAILED"
        assert res["http_status"] == 429
        assert "rate_limit_exceeded" in res["error"]

    def test_messaging_invalid_recipient_failure(self, messaging_simulator: MockMessagingSimulator):
        messaging_simulator.set_scenario_override("invalid_bad_addr", "INVALID_RECIPIENT")
        res = messaging_simulator.simulate_dispatch(
            channel=ActionChannel.SMS,
            destination_url="http://localhost:8002/messages",
            recipient="invalid_bad_addr",
            message_body="Notice",
        )

        assert res["status"] == "FAILED"
        assert res["http_status"] == 400
        assert "invalid_recipient" in res["error"]

    def test_messaging_gateway_timeout_failure(self, messaging_simulator: MockMessagingSimulator):
        messaging_simulator.set_scenario_override("timeout_user@sandbox.internal", "GATEWAY_TIMEOUT")
        res = messaging_simulator.simulate_dispatch(
            channel=ActionChannel.WHATSAPP,
            destination_url="http://localhost:8002/messages",
            recipient="timeout_user@sandbox.internal",
            message_body="Notice",
        )

        assert res["status"] == "FAILED"
        assert res["http_status"] == 504
        assert "gateway_timeout" in res["error"]

    def test_messaging_simulator_blocks_production_egress(self, messaging_simulator: MockMessagingSimulator):
        with pytest.raises(SandboxViolationError, match="Production egress blocked"):
            messaging_simulator.simulate_dispatch(
                channel=ActionChannel.SMS,
                destination_url="https://api.twilio.com/2010-04-01/Accounts",
                recipient="+1234567890",
                message_body="Notice",
            )


class TestActionExecutorSimulatorIntegration:
    """Verifies end-to-end ActionExecutor execution integrated with Mock Simulators."""

    @pytest.fixture
    def authorizer(self) -> CryptographicAuthorizer:
        return CryptographicAuthorizer(signing_secret="secure-secret-simulators-12345678")

    @pytest.fixture
    def executor_with_simulators(
        self,
        authorizer: CryptographicAuthorizer,
        sandbox_guard: SandboxGuard,
        payment_simulator: MockPaymentSimulator,
        messaging_simulator: MockMessagingSimulator,
    ) -> ActionExecutor:
        handler = create_sandbox_action_handler(
            payment_simulator=payment_simulator,
            messaging_simulator=messaging_simulator,
            sandbox_guard=sandbox_guard,
        )
        return ActionExecutor(
            authorizer=authorizer,
            kill_switch=KillSwitchManager(),
            circuit_breakers=GranularCircuitBreakerRegistry(),
            capacity_governor=CapacityGovernor(),
            sandbox_guard=sandbox_guard,
            audit_logger=CryptographicAuditLogger(),
            sandbox_handler=handler,
        )

    def test_executor_payment_retry_through_simulator(
        self,
        executor_with_simulators: ActionExecutor,
        authorizer: CryptographicAuthorizer,
        payment_simulator: MockPaymentSimulator,
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = authorizer.mint_authorization(
            case_id="case_sim_pay_1",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_sim_100",
            max_amount_in_cents=25000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_sim_100",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_sim_pay_100",
            current_time=t0,
        )

        request = ExecutionRequest(
            case_id="case_sim_pay_1",
            customer_id="cust_sim_100",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=25000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_sim_pay_100",
            action_payload={"invoice_id": "inv_sim_100", "amount_in_cents": 25000, "currency": "INR"},
        )

        result = executor_with_simulators.execute_action(request=request, token=token, current_time=t0)
        assert result.status == ExecutionStatus.SUCCESS
        assert result.response_payload["status"] == "SUCCESS"
        assert result.response_payload["charge_id"].startswith("ch_mock_")
        assert len(payment_simulator.history) == 1

    def test_executor_email_notification_through_simulator(
        self,
        executor_with_simulators: ActionExecutor,
        authorizer: CryptographicAuthorizer,
        messaging_simulator: MockMessagingSimulator,
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = authorizer.mint_authorization(
            case_id="case_sim_msg_1",
            action_type=ActionType.SEND_NOTIFICATION,
            customer_id="cust_sim_200",
            max_amount_in_cents=1,  # Non-monetary action has nominal bound
            currency="INR",
            channel=ActionChannel.EMAIL,
            policy_version="v1.0",
            decision_id="dec_sim_200",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_sim_msg_200",
            current_time=t0,
        )

        request = ExecutionRequest(
            case_id="case_sim_msg_1",
            customer_id="cust_sim_200",
            action_type=ActionType.SEND_NOTIFICATION,
            channel=ActionChannel.EMAIL,
            amount_in_cents=1,
            currency="INR",
            destination_url="http://localhost:8002/messages",
            idempotency_key="idemp_sim_msg_200",
            action_payload={
                "recipient": "cust_200@sandbox.internal",
                "message_body": "Update your payment method",
                "template_id": "tpl_update_card",
            },
        )

        result = executor_with_simulators.execute_action(request=request, token=token, current_time=t0)
        assert result.status == ExecutionStatus.SUCCESS
        assert result.response_payload["status"] == "SUCCESS"
        assert result.response_payload["delivery_status"] == "DELIVERED"
        assert len(messaging_simulator.history) == 1
