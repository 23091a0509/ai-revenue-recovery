"""Unit, security, and idempotency tests for ActionExecutor (TICKET-10 & TICKET-12).

Architecture Baseline: Frozen Architecture Baseline v11.
Enforces:
- INV-03: Capability-based Action Authorization
- INV-04: Executor acts ONLY on valid signed token (strict independent request-to-token scope binding)
- INV-05: Strict MVP Sandbox Isolation (via integrated SandboxGuard evaluated before capacity reservation)
- INV-16: Idempotency across execution and retry
"""

import concurrent.futures
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
import pytest

from src.revenue_recovery.foundation.audit import CryptographicAuditLogger
from src.revenue_recovery.foundation.events import (
    ActionChannel,
    ActionType,
    ExecutionStatus,
    FailureReason,
)
from src.revenue_recovery.safety import (
    ActionAuthorization,
    AuthorizationVerificationError,
    CapacityExceededError,
    CapacityGovernor,
    CircuitBrokenError,
    CryptographicAuthorizer,
    GranularCircuitBreakerRegistry,
    KillSwitchActiveError,
    KillSwitchManager,
)
from src.revenue_recovery.executor import (
    ActionExecutor,
    ExecutionRequest,
    ExecutionResult,
    IdempotencyConflictError,
    IdempotencyStore,
    MockMessagingSimulator,
    MockPaymentSimulator,
    SandboxGuard,
    SandboxViolationError,
    create_sandbox_action_handler,
)


@pytest.fixture
def signing_secret() -> str:
    return "secure-authorizer-executor-secret-12345678"


@pytest.fixture
def authorizer(signing_secret: str) -> CryptographicAuthorizer:
    return CryptographicAuthorizer(signing_secret=signing_secret)


@pytest.fixture
def kill_switch() -> KillSwitchManager:
    return KillSwitchManager()


@pytest.fixture
def circuit_breakers() -> GranularCircuitBreakerRegistry:
    return GranularCircuitBreakerRegistry(default_failure_threshold=2, default_recovery_timeout_seconds=10.0)


@pytest.fixture
def capacity_governor() -> CapacityGovernor:
    return CapacityGovernor(max_actions_per_window=10, max_volume_in_cents_per_window=500000, window_seconds=60.0)


@pytest.fixture
def sandbox_guard() -> SandboxGuard:
    return SandboxGuard(dns_resolver=lambda host, port: ["127.0.0.1"])


@pytest.fixture
def audit_logger() -> CryptographicAuditLogger:
    return CryptographicAuditLogger()


@pytest.fixture
def idempotency_store() -> IdempotencyStore:
    return IdempotencyStore()


@pytest.fixture
def mock_handler() -> MagicMock:
    handler = MagicMock()
    handler.return_value = {
        "status": "SUCCESS",
        "mock_charge_id": "ch_mock_12345",
        "message": "Approved in sandbox",
    }
    return handler


@pytest.fixture
def executor(
    authorizer: CryptographicAuthorizer,
    kill_switch: KillSwitchManager,
    circuit_breakers: GranularCircuitBreakerRegistry,
    capacity_governor: CapacityGovernor,
    sandbox_guard: SandboxGuard,
    audit_logger: CryptographicAuditLogger,
    idempotency_store: IdempotencyStore,
    mock_handler: MagicMock,
) -> ActionExecutor:
    return ActionExecutor(
        authorizer=authorizer,
        kill_switch=kill_switch,
        circuit_breakers=circuit_breakers,
        capacity_governor=capacity_governor,
        sandbox_guard=sandbox_guard,
        audit_logger=audit_logger,
        idempotency_store=idempotency_store,
        sandbox_handler=mock_handler,
    )


class TestExecutorHealthyExecution:
    """Verifies standard happy path execution through all 8 stages."""

    def test_healthy_token_executes_successfully(
        self,
        executor: ActionExecutor,
        authorizer: CryptographicAuthorizer,
        audit_logger: CryptographicAuditLogger,
        mock_handler: MagicMock,
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = authorizer.mint_authorization(
            case_id="case_exec_001",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_exec_001",
            max_amount_in_cents=10000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_exec_001",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_exec_001",
            current_time=t0,
        )

        request = ExecutionRequest(
            case_id="case_exec_001",
            customer_id="cust_exec_001",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=10000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_exec_001",
            action_payload={"invoice_id": "inv_001"},
        )

        result = executor.execute_action(
            request=request,
            token=token,
            current_time=t0,
        )

        assert isinstance(result, ExecutionResult)
        assert result.status == ExecutionStatus.SUCCESS
        assert result.idempotency_key == "idemp_exec_001"
        assert result.case_id == "case_exec_001"
        assert result.customer_id == "cust_exec_001"
        assert result.amount_in_cents == 10000
        assert result.response_payload["mock_charge_id"] == "ch_mock_12345"

        # Verify simulator handler invoked exactly once
        mock_handler.assert_called_once_with(
            ActionChannel.DIRECT_PAYMENT_GATEWAY,
            "http://localhost:8001/charge",
            {"invoice_id": "inv_001"},
        )

        # Verify audit log entry
        assert len(audit_logger.entries) == 1
        audit_entry = audit_logger.entries[0]
        assert audit_entry.event_type == "ACTION_EXECUTED"
        assert audit_entry.payload["case_id"] == "case_exec_001"
        assert audit_entry.payload["status"] == "SUCCESS"
        assert audit_entry.payload["token_signature"] == token.signature


class TestExecutorIndependentRequestScopeBinding:
    """Verifies that the Executor independently validates the request against the signed token."""

    @pytest.fixture
    def base_token(self, authorizer: CryptographicAuthorizer) -> ActionAuthorization:
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        return authorizer.mint_authorization(
            case_id="case_valid_100",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_valid_100",
            max_amount_in_cents=50000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_valid_100",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_valid_100",
            current_time=t0,
        )

    def test_mismatched_customer_id_rejected(self, executor: ActionExecutor, base_token: ActionAuthorization):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        request = ExecutionRequest(
            case_id="case_valid_100",
            customer_id="cust_ATTACKER_200",  # Mismatch
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=10000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_valid_100",
        )
        with pytest.raises(AuthorizationVerificationError, match="Customer mismatch"):
            executor.execute_action(request=request, token=base_token, current_time=t0)

    def test_mismatched_currency_rejected(self, executor: ActionExecutor, base_token: ActionAuthorization):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        request = ExecutionRequest(
            case_id="case_valid_100",
            customer_id="cust_valid_100",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=10000,
            currency="USD",  # Mismatch
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_valid_100",
        )
        with pytest.raises(AuthorizationVerificationError, match="Currency mismatch"):
            executor.execute_action(request=request, token=base_token, current_time=t0)

    def test_mismatched_channel_rejected(self, executor: ActionExecutor, base_token: ActionAuthorization):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        request = ExecutionRequest(
            case_id="case_valid_100",
            customer_id="cust_valid_100",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.SMS,  # Mismatch
            amount_in_cents=10000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_valid_100",
        )
        with pytest.raises(AuthorizationVerificationError, match="Channel mismatch"):
            executor.execute_action(request=request, token=base_token, current_time=t0)

    def test_mismatched_case_id_rejected(self, executor: ActionExecutor, base_token: ActionAuthorization):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        request = ExecutionRequest(
            case_id="case_DIFFERENT_999",  # Mismatch
            customer_id="cust_valid_100",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=10000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_valid_100",
        )
        with pytest.raises(AuthorizationVerificationError, match="Scope mismatch: Request case_id"):
            executor.execute_action(request=request, token=base_token, current_time=t0)

    def test_mismatched_action_type_rejected(self, executor: ActionExecutor, base_token: ActionAuthorization):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        request = ExecutionRequest(
            case_id="case_valid_100",
            customer_id="cust_valid_100",
            action_type=ActionType.OFFER_PAYMENT_PLAN,  # Mismatch
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=10000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_valid_100",
        )
        with pytest.raises(AuthorizationVerificationError, match="Scope mismatch: Request action_type"):
            executor.execute_action(request=request, token=base_token, current_time=t0)

    def test_mismatched_idempotency_key_rejected(self, executor: ActionExecutor, base_token: ActionAuthorization):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        request = ExecutionRequest(
            case_id="case_valid_100",
            customer_id="cust_valid_100",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=10000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_DIFFERENT_999",  # Mismatch
        )
        with pytest.raises(AuthorizationVerificationError, match="Scope mismatch: Request idempotency_key"):
            executor.execute_action(request=request, token=base_token, current_time=t0)


class TestExecutorUnsignedOrTamperedTokenRejected:
    """Verifies that the Executor acts ONLY on valid signed tokens (INV-04)."""

    def test_forged_signature_token_rejected_before_execution(
        self,
        executor: ActionExecutor,
        authorizer: CryptographicAuthorizer,
        mock_handler: MagicMock,
        audit_logger: CryptographicAuditLogger,
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = authorizer.mint_authorization(
            case_id="case_forged_1",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_forged_1",
            max_amount_in_cents=5000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_forged_1",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_forged_1",
            current_time=t0,
        )

        tampered_token = token.model_copy(update={"signature": "0" * 64})
        request = ExecutionRequest(
            case_id="case_forged_1",
            customer_id="cust_forged_1",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=5000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_forged_1",
        )

        with pytest.raises(AuthorizationVerificationError, match="Cryptographic signature mismatch"):
            executor.execute_action(
                request=request,
                token=tampered_token,
                current_time=t0,
            )

        # Zero handler calls, zero audit logs
        mock_handler.assert_not_called()
        assert len(audit_logger.entries) == 0

    def test_expired_token_rejected_before_execution(
        self,
        executor: ActionExecutor,
        authorizer: CryptographicAuthorizer,
        mock_handler: MagicMock,
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = authorizer.mint_authorization(
            case_id="case_exp_1",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_exp_1",
            max_amount_in_cents=5000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_exp_1",
            expires_at=t0 + timedelta(minutes=2),
            idempotency_key="idemp_exp_1",
            current_time=t0,
        )
        request = ExecutionRequest(
            case_id="case_exp_1",
            customer_id="cust_exp_1",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=5000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_exp_1",
        )

        t_after_expiry = t0 + timedelta(minutes=5)
        with pytest.raises(AuthorizationVerificationError, match="Token has expired"):
            executor.execute_action(
                request=request,
                token=token,
                current_time=t_after_expiry,
            )

        mock_handler.assert_not_called()

    def test_requested_amount_exceeding_token_bound_rejected(
        self,
        executor: ActionExecutor,
        authorizer: CryptographicAuthorizer,
        mock_handler: MagicMock,
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = authorizer.mint_authorization(
            case_id="case_bound_1",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_bound_1",
            max_amount_in_cents=5000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_bound_1",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_bound_1",
            current_time=t0,
        )
        request = ExecutionRequest(
            case_id="case_bound_1",
            customer_id="cust_bound_1",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=7000,  # Exceeds max 5000
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_bound_1",
        )

        with pytest.raises(AuthorizationVerificationError, match="Requested amount .* exceeds authorized upper bound"):
            executor.execute_action(
                request=request,
                token=token,
                current_time=t0,
            )

        mock_handler.assert_not_called()


class TestExecutorSafetyGatesAndShortCircuit:
    """Verifies that all safety gates short-circuit before handler dispatch."""

    def test_kill_switch_blocks_execution(
        self,
        executor: ActionExecutor,
        authorizer: CryptographicAuthorizer,
        kill_switch: KillSwitchManager,
        mock_handler: MagicMock,
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = authorizer.mint_authorization(
            case_id="case_ks_1",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_ks_1",
            max_amount_in_cents=5000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_ks_1",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_ks_1",
            current_time=t0,
        )
        request = ExecutionRequest(
            case_id="case_ks_1",
            customer_id="cust_ks_1",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=5000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_ks_1",
        )

        kill_switch.activate_global(reason="Emergency freeze", activated_by="security_admin")

        with pytest.raises(KillSwitchActiveError, match="Execution halted by GLOBAL kill switch"):
            executor.execute_action(
                request=request,
                token=token,
                current_time=t0,
            )

        mock_handler.assert_not_called()

    def test_circuit_breaker_blocks_execution(
        self,
        executor: ActionExecutor,
        authorizer: CryptographicAuthorizer,
        circuit_breakers: GranularCircuitBreakerRegistry,
        mock_handler: MagicMock,
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = authorizer.mint_authorization(
            case_id="case_cb_1",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_cb_1",
            max_amount_in_cents=5000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_cb_1",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_cb_1",
            current_time=t0,
        )
        request = ExecutionRequest(
            case_id="case_cb_1",
            customer_id="cust_cb_1",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=5000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_cb_1",
        )

        circuit_breakers.record_failure(ActionChannel.DIRECT_PAYMENT_GATEWAY, current_time=t0)
        circuit_breakers.record_failure(ActionChannel.DIRECT_PAYMENT_GATEWAY, current_time=t0)

        with pytest.raises(CircuitBrokenError, match="is OPEN and blocking execution"):
            executor.execute_action(
                request=request,
                token=token,
                current_time=t0,
            )

        mock_handler.assert_not_called()

    def test_capacity_governor_blocks_execution(
        self,
        executor: ActionExecutor,
        authorizer: CryptographicAuthorizer,
        capacity_governor: CapacityGovernor,
        mock_handler: MagicMock,
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        # Governor max volume is 500,000 cents
        token = authorizer.mint_authorization(
            case_id="case_cap_1",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_cap_1",
            max_amount_in_cents=600000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_cap_1",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_cap_1",
            current_time=t0,
        )
        request = ExecutionRequest(
            case_id="case_cap_1",
            customer_id="cust_cap_1",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=600000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_cap_1",
        )

        with pytest.raises(CapacityExceededError, match="Monetary volume limit exceeded"):
            executor.execute_action(
                request=request,
                token=token,
                current_time=t0,
            )

        mock_handler.assert_not_called()

    def test_sandbox_egress_firewall_blocks_production_url_without_consuming_capacity(
        self,
        executor: ActionExecutor,
        authorizer: CryptographicAuthorizer,
        capacity_governor: CapacityGovernor,
        mock_handler: MagicMock,
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = authorizer.mint_authorization(
            case_id="case_firewall_1",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_firewall_1",
            max_amount_in_cents=5000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_firewall_1",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_firewall_1",
            current_time=t0,
        )
        request = ExecutionRequest(
            case_id="case_firewall_1",
            customer_id="cust_firewall_1",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=5000,
            currency="INR",
            destination_url="https://api.stripe.com/v1/charges",
            idempotency_key="idemp_firewall_1",
        )

        with pytest.raises(SandboxViolationError, match="Production egress blocked"):
            executor.execute_action(
                request=request,
                token=token,
                current_time=t0,
            )

        mock_handler.assert_not_called()

        # Proves zero capacity was consumed
        count, vol = capacity_governor.get_current_utilization(current_time=t0)
        assert count == 0
        assert vol == 0


class TestExecutorIdempotencyAndConcurrency:
    """Verifies exact idempotency caching, conflict rejection, and concurrent safety."""

    def test_replay_with_identical_parameters_returns_cached_result(
        self,
        executor: ActionExecutor,
        authorizer: CryptographicAuthorizer,
        mock_handler: MagicMock,
        audit_logger: CryptographicAuditLogger,
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = authorizer.mint_authorization(
            case_id="case_idem_1",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_idem_1",
            max_amount_in_cents=5000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_idem_1",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_repeat_key_100",
            current_time=t0,
        )
        request = ExecutionRequest(
            case_id="case_idem_1",
            customer_id="cust_idem_1",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=5000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_repeat_key_100",
        )

        res1 = executor.execute_action(
            request=request,
            token=token,
            current_time=t0,
        )
        assert res1.status == ExecutionStatus.SUCCESS

        # Second execution with exact same request
        res2 = executor.execute_action(
            request=request,
            token=token,
            current_time=t0 + timedelta(seconds=10),
        )

        # Returns identical result
        assert res1 == res2

        # Handler invoked EXACTLY ONCE (zero duplicate side-effects)
        assert mock_handler.call_count == 1

        # Audit log has only 1 execution entry
        assert len(audit_logger.entries) == 1

    def test_failed_execution_returns_failed_result_and_records_idempotency(
        self,
        executor: ActionExecutor,
        authorizer: CryptographicAuthorizer,
        mock_handler: MagicMock,
        circuit_breakers: GranularCircuitBreakerRegistry,
    ):
        # Simulator returns a 402 Insufficient Funds / Decline failure
        mock_handler.return_value = {
            "status": "FAILED",
            "http_status": 402,
            "error": "card_declined_insufficient_funds",
        }

        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = authorizer.mint_authorization(
            case_id="case_fail_1",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_fail_1",
            max_amount_in_cents=5000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_fail_1",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_failed_key_150",
            current_time=t0,
        )
        request = ExecutionRequest(
            case_id="case_fail_1",
            customer_id="cust_fail_1",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=5000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_failed_key_150",
        )

        res1 = executor.execute_action(request=request, token=token, current_time=t0)
        assert res1.status == ExecutionStatus.FAILED
        assert res1.error_message == "card_declined_insufficient_funds"

        # Duplicate retry with the same key returns the cached failed result without re-executing
        res2 = executor.execute_action(request=request, token=token, current_time=t0 + timedelta(seconds=5))
        assert res2 == res1
        assert mock_handler.call_count == 1

        # Circuit breaker recorded the failure
        breaker = circuit_breakers.get_or_create(ActionChannel.DIRECT_PAYMENT_GATEWAY)
        assert breaker._consecutive_failures == 1

    def test_replay_with_conflicting_parameters_fails_closed(
        self,
        executor: ActionExecutor,
        authorizer: CryptographicAuthorizer,
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        token1 = authorizer.mint_authorization(
            case_id="case_conflict_1",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_conflict_1",
            max_amount_in_cents=5000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_conflict_1",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_conflict_key_200",
            current_time=t0,
        )
        req1 = ExecutionRequest(
            case_id="case_conflict_1",
            customer_id="cust_conflict_1",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=5000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_conflict_key_200",
        )

        executor.execute_action(
            request=req1,
            token=token1,
            current_time=t0,
        )

        token2_conflicting = authorizer.mint_authorization(
            case_id="case_DIFFERENT_2",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_conflict_1",
            max_amount_in_cents=5000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_conflict_2",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_conflict_key_200",  # Same key, different case_id
            current_time=t0,
        )
        req2_conflicting = ExecutionRequest(
            case_id="case_DIFFERENT_2",
            customer_id="cust_conflict_1",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=5000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_conflict_key_200",
        )

        with pytest.raises(IdempotencyConflictError, match="Conflicting re-execution rejected"):
            executor.execute_action(
                request=req2_conflicting,
                token=token2_conflicting,
                current_time=t0,
            )

    def test_concurrent_duplicate_requests_execute_handler_only_once(
        self,
        executor: ActionExecutor,
        authorizer: CryptographicAuthorizer,
        mock_handler: MagicMock,
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = authorizer.mint_authorization(
            case_id="case_race_1",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_race_1",
            max_amount_in_cents=5000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_race_1",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_race_key_300",
            current_time=t0,
        )
        request = ExecutionRequest(
            case_id="case_race_1",
            customer_id="cust_race_1",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=5000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_race_key_300",
        )

        def run_execution():
            return executor.execute_action(
                request=request,
                token=token,
                current_time=t0,
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(run_execution) for _ in range(8)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # All 8 concurrent callers received the identical ExecutionResult
        assert len(results) == 8
        first_res = results[0]
        for r in results:
            assert r == first_res

        # Handler was dispatched EXACTLY ONCE
        assert mock_handler.call_count == 1


class TestExecutorIntegratedRealSimulatorPipeline:
    """
    End-to-End Milestone 3 Integration Tests.
    Exercises real ActionExecutor -> real create_sandbox_action_handler -> real MockPaymentSimulator
    and MockMessagingSimulator components without mock handlers.
    """

    @pytest.fixture
    def payment_simulator(self, sandbox_guard: SandboxGuard) -> MockPaymentSimulator:
        return MockPaymentSimulator(sandbox_guard=sandbox_guard)

    @pytest.fixture
    def messaging_simulator(self, sandbox_guard: SandboxGuard) -> MockMessagingSimulator:
        return MockMessagingSimulator(sandbox_guard=sandbox_guard)

    @pytest.fixture
    def integrated_executor(
        self,
        authorizer: CryptographicAuthorizer,
        kill_switch: KillSwitchManager,
        circuit_breakers: GranularCircuitBreakerRegistry,
        capacity_governor: CapacityGovernor,
        sandbox_guard: SandboxGuard,
        audit_logger: CryptographicAuditLogger,
        idempotency_store: IdempotencyStore,
        payment_simulator: MockPaymentSimulator,
        messaging_simulator: MockMessagingSimulator,
    ) -> ActionExecutor:
        real_handler = create_sandbox_action_handler(
            payment_simulator=payment_simulator,
            messaging_simulator=messaging_simulator,
            sandbox_guard=sandbox_guard,
        )
        return ActionExecutor(
            authorizer=authorizer,
            kill_switch=kill_switch,
            circuit_breakers=circuit_breakers,
            capacity_governor=capacity_governor,
            sandbox_guard=sandbox_guard,
            audit_logger=audit_logger,
            idempotency_store=idempotency_store,
            sandbox_handler=real_handler,
        )

    def test_integrated_payment_charge_execution_and_replay(
        self,
        integrated_executor: ActionExecutor,
        authorizer: CryptographicAuthorizer,
        payment_simulator: MockPaymentSimulator,
        audit_logger: CryptographicAuditLogger,
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = authorizer.mint_authorization(
            case_id="case_int_pay_01",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_int_01",
            max_amount_in_cents=35000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_int_01",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_int_pay_01",
            current_time=t0,
        )
        request = ExecutionRequest(
            case_id="case_int_pay_01",
            customer_id="cust_int_01",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=35000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_int_pay_01",
            action_payload={"invoice_id": "inv_int_01", "amount_in_cents": 35000, "currency": "INR"},
        )

        res1 = integrated_executor.execute_action(request=request, token=token, current_time=t0)
        assert res1.status == ExecutionStatus.SUCCESS
        assert res1.response_payload["charge_id"].startswith("ch_mock_")
        assert len(payment_simulator.history) == 1

        # Replay with same key returns cached result and does NOT invoke simulator again
        res2 = integrated_executor.execute_action(request=request, token=token, current_time=t0 + timedelta(seconds=10))
        assert res2 == res1
        assert len(payment_simulator.history) == 1
        assert len(audit_logger.entries) == 1

    def test_integrated_payment_insufficient_funds_failure_and_circuit_health(
        self,
        integrated_executor: ActionExecutor,
        authorizer: CryptographicAuthorizer,
        payment_simulator: MockPaymentSimulator,
        circuit_breakers: GranularCircuitBreakerRegistry,
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        payment_simulator.set_scenario_override("inv_int_fail_02", "INSUFFICIENT_FUNDS")

        token = authorizer.mint_authorization(
            case_id="case_int_pay_02",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_int_02",
            max_amount_in_cents=20000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_int_02",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_int_pay_02",
            current_time=t0,
        )
        request = ExecutionRequest(
            case_id="case_int_pay_02",
            customer_id="cust_int_02",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=20000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_int_pay_02",
            action_payload={"invoice_id": "inv_int_fail_02", "amount_in_cents": 20000, "currency": "INR"},
        )

        res = integrated_executor.execute_action(request=request, token=token, current_time=t0)
        assert res.status == ExecutionStatus.FAILED
        assert res.response_payload["http_status"] == 402
        assert res.response_payload["failure_code"] == FailureReason.INSUFFICIENT_FUNDS.value

        # Breaker recorded the failure
        breaker = circuit_breakers.get_or_create(ActionChannel.DIRECT_PAYMENT_GATEWAY)
        assert breaker._consecutive_failures == 1

    def test_integrated_messaging_dispatch_across_channels(
        self,
        integrated_executor: ActionExecutor,
        authorizer: CryptographicAuthorizer,
        messaging_simulator: MockMessagingSimulator,
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        channels = [ActionChannel.EMAIL, ActionChannel.SMS, ActionChannel.WHATSAPP]

        for i, ch in enumerate(channels):
            token = authorizer.mint_authorization(
                case_id=f"case_int_msg_{i}",
                action_type=ActionType.SEND_NOTIFICATION,
                customer_id=f"cust_msg_{i}",
                max_amount_in_cents=1,
                currency="INR",
                channel=ch,
                policy_version="v1.0",
                decision_id=f"dec_msg_{i}",
                expires_at=t0 + timedelta(minutes=5),
                idempotency_key=f"idemp_msg_{i}",
                current_time=t0,
            )
            request = ExecutionRequest(
                case_id=f"case_int_msg_{i}",
                customer_id=f"cust_msg_{i}",
                action_type=ActionType.SEND_NOTIFICATION,
                channel=ch,
                amount_in_cents=1,
                currency="INR",
                destination_url="http://localhost:8002/messages",
                idempotency_key=f"idemp_msg_{i}",
                action_payload={"recipient": f"user_{i}@sandbox.internal", "message_body": "Payment notice"},
            )

            res = integrated_executor.execute_action(request=request, token=token, current_time=t0)
            assert res.status == ExecutionStatus.SUCCESS
            assert res.response_payload["delivery_status"] == "DELIVERED"
            assert res.response_payload["message_id"].startswith("msg_mock_")

        assert len(messaging_simulator.history) == 3
