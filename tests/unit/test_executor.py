"""Unit and security tests for Idempotent Action Executor (TICKET-10).

Architecture Baseline: Frozen Architecture Baseline v11.
Enforces:
- INV-03: Capability-based Action Authorization
- INV-04: Executor acts ONLY on valid signed token
- INV-05: Strict MVP Sandbox Isolation (via integrated SandboxGuard)
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
    ExecutionResult,
    IdempotencyConflictError,
    IdempotencyStore,
    SandboxGuard,
    SandboxViolationError,
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

        result = executor.execute_action(
            token=token,
            requested_amount_in_cents=10000,
            destination_url="http://localhost:8001/charge",
            action_payload={"invoice_id": "inv_001"},
            current_time=t0,
        )

        assert isinstance(result, ExecutionResult)
        assert result.status == ExecutionStatus.SUCCESS
        assert result.idempotency_key == "idemp_exec_001"
        assert result.case_id == "case_exec_001"
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

        with pytest.raises(AuthorizationVerificationError, match="Cryptographic signature mismatch"):
            executor.execute_action(
                token=tampered_token,
                requested_amount_in_cents=5000,
                destination_url="http://localhost:8001/charge",
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

        t_after_expiry = t0 + timedelta(minutes=5)
        with pytest.raises(AuthorizationVerificationError, match="Token has expired"):
            executor.execute_action(
                token=token,
                requested_amount_in_cents=5000,
                destination_url="http://localhost:8001/charge",
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

        # Attempt to execute 7000 cents when bound is 5000
        with pytest.raises(AuthorizationVerificationError, match="Requested amount .* exceeds authorized upper bound"):
            executor.execute_action(
                token=token,
                requested_amount_in_cents=7000,
                destination_url="http://localhost:8001/charge",
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

        kill_switch.activate_global(reason="Emergency freeze", activated_by="security_admin")

        with pytest.raises(KillSwitchActiveError, match="Execution halted by GLOBAL kill switch"):
            executor.execute_action(
                token=token,
                requested_amount_in_cents=5000,
                destination_url="http://localhost:8001/charge",
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

        circuit_breakers.record_failure(ActionChannel.DIRECT_PAYMENT_GATEWAY, current_time=t0)
        circuit_breakers.record_failure(ActionChannel.DIRECT_PAYMENT_GATEWAY, current_time=t0)

        with pytest.raises(CircuitBrokenError, match="is OPEN and blocking execution"):
            executor.execute_action(
                token=token,
                requested_amount_in_cents=5000,
                destination_url="http://localhost:8001/charge",
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

        with pytest.raises(CapacityExceededError, match="Monetary volume limit exceeded"):
            executor.execute_action(
                token=token,
                requested_amount_in_cents=600000,
                destination_url="http://localhost:8001/charge",
                current_time=t0,
            )

        mock_handler.assert_not_called()

    def test_sandbox_egress_firewall_blocks_production_url(
        self,
        executor: ActionExecutor,
        authorizer: CryptographicAuthorizer,
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

        with pytest.raises(SandboxViolationError, match="Production egress blocked"):
            executor.execute_action(
                token=token,
                requested_amount_in_cents=5000,
                destination_url="https://api.stripe.com/v1/charges",
                current_time=t0,
            )

        mock_handler.assert_not_called()


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

        res1 = executor.execute_action(
            token=token,
            requested_amount_in_cents=5000,
            destination_url="http://localhost:8001/charge",
            current_time=t0,
        )
        assert res1.status == ExecutionStatus.SUCCESS

        # Second execution with exact same token and parameters
        res2 = executor.execute_action(
            token=token,
            requested_amount_in_cents=5000,
            destination_url="http://localhost:8001/charge",
            current_time=t0 + timedelta(seconds=10),
        )

        # Returns identical result
        assert res1 == res2

        # Handler invoked EXACTLY ONCE (zero duplicate side-effects)
        assert mock_handler.call_count == 1

        # Audit log has only 1 execution entry
        assert len(audit_logger.entries) == 1

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

        executor.execute_action(
            token=token1,
            requested_amount_in_cents=5000,
            destination_url="http://localhost:8001/charge",
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

        with pytest.raises(IdempotencyConflictError, match="Conflicting re-execution rejected"):
            executor.execute_action(
                token=token2_conflicting,
                requested_amount_in_cents=5000,
                destination_url="http://localhost:8001/charge",
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

        def run_execution():
            return executor.execute_action(
                token=token,
                requested_amount_in_cents=5000,
                destination_url="http://localhost:8001/charge",
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
