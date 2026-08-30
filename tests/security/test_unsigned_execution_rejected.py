"""Adversarial Security Tests for Invariant INV-04:
"Executor acts ONLY on valid signed token".

Architecture Baseline: Frozen Architecture Baseline v11.
Enforces:
- Every execution MUST be authorized by a cryptographically valid, unexpired,
  and properly scoped ActionAuthorization token.
- Unsigned, forged, expired, tampered, or mis-scoped tokens MUST fail closed
  BEFORE any simulator dispatch, capacity reservation, or audit leakage.
"""

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
    CapacityGovernor,
    CryptographicAuthorizer,
    GranularCircuitBreakerRegistry,
    KillSwitchManager,
)
from src.revenue_recovery.executor import (
    ActionExecutor,
    ExecutionRequest,
    IdempotencyStore,
    SandboxGuard,
)


@pytest.fixture
def signing_secret() -> str:
    return "secure-adversarial-test-secret-12345678"


@pytest.fixture
def authorizer(signing_secret: str) -> CryptographicAuthorizer:
    return CryptographicAuthorizer(signing_secret=signing_secret)


@pytest.fixture
def mock_handler() -> MagicMock:
    handler = MagicMock()
    handler.return_value = {"status": "SUCCESS", "charge_id": "ch_mock_123"}
    return handler


@pytest.fixture
def audit_logger() -> CryptographicAuditLogger:
    return CryptographicAuditLogger()


@pytest.fixture
def capacity_governor() -> CapacityGovernor:
    return CapacityGovernor()


@pytest.fixture
def executor(
    authorizer: CryptographicAuthorizer,
    audit_logger: CryptographicAuditLogger,
    capacity_governor: CapacityGovernor,
    mock_handler: MagicMock,
) -> ActionExecutor:
    return ActionExecutor(
        authorizer=authorizer,
        kill_switch=KillSwitchManager(),
        circuit_breakers=GranularCircuitBreakerRegistry(),
        capacity_governor=capacity_governor,
        sandbox_guard=SandboxGuard(dns_resolver=lambda host, port: ["127.0.0.1"]),
        audit_logger=audit_logger,
        idempotency_store=IdempotencyStore(),
        sandbox_handler=mock_handler,
    )


class TestUnsignedExecutionSecurityBoundaries:
    """Proves that unauthenticated or forged tokens cannot execute under any circumstance (INV-04)."""

    def test_forged_hmac_signature_strictly_rejected(
        self,
        executor: ActionExecutor,
        authorizer: CryptographicAuthorizer,
        mock_handler: MagicMock,
        audit_logger: CryptographicAuditLogger,
        capacity_governor: CapacityGovernor,
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = authorizer.mint_authorization(
            case_id="case_sec_001",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_sec_001",
            max_amount_in_cents=10000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_sec_001",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_sec_001",
            current_time=t0,
        )

        forged_token = token.model_copy(update={"signature": "e" * 64})
        request = ExecutionRequest(
            case_id="case_sec_001",
            customer_id="cust_sec_001",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=10000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_sec_001",
        )

        with pytest.raises(AuthorizationVerificationError, match="Cryptographic signature mismatch"):
            executor.execute_action(request=request, token=forged_token, current_time=t0)

        # Proves ZERO dispatch, ZERO capacity consumed, ZERO audit entries
        mock_handler.assert_not_called()
        count, vol = capacity_governor.get_current_utilization(current_time=t0)
        assert count == 0
        assert vol == 0
        assert len(audit_logger.entries) == 0

    def test_token_minted_with_different_secret_rejected(
        self,
        executor: ActionExecutor,
        mock_handler: MagicMock,
        audit_logger: CryptographicAuditLogger,
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        foreign_authorizer = CryptographicAuthorizer(signing_secret="attacker-rogue-secret-99999999")
        foreign_token = foreign_authorizer.mint_authorization(
            case_id="case_sec_002",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_sec_002",
            max_amount_in_cents=10000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_sec_002",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_sec_002",
            current_time=t0,
        )

        request = ExecutionRequest(
            case_id="case_sec_002",
            customer_id="cust_sec_002",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=10000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_sec_002",
        )

        with pytest.raises(AuthorizationVerificationError, match="Cryptographic signature mismatch"):
            executor.execute_action(request=request, token=foreign_token, current_time=t0)

        mock_handler.assert_not_called()
        assert len(audit_logger.entries) == 0

    def test_expired_token_strictly_rejected(
        self,
        executor: ActionExecutor,
        authorizer: CryptographicAuthorizer,
        mock_handler: MagicMock,
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = authorizer.mint_authorization(
            case_id="case_sec_003",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_sec_003",
            max_amount_in_cents=10000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_sec_003",
            expires_at=t0 + timedelta(seconds=60),
            idempotency_key="idemp_sec_003",
            current_time=t0,
        )

        request = ExecutionRequest(
            case_id="case_sec_003",
            customer_id="cust_sec_003",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=10000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_sec_003",
        )

        t_after_expiry = t0 + timedelta(seconds=61)
        with pytest.raises(AuthorizationVerificationError, match="Token has expired"):
            executor.execute_action(request=request, token=token, current_time=t_after_expiry)

        mock_handler.assert_not_called()


class TestScopeTamperingSecurityBoundaries:
    """Proves that any discrepancy between independent request and signed token fails closed (INV-04)."""

    @pytest.fixture
    def valid_token(self, authorizer: CryptographicAuthorizer) -> ActionAuthorization:
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        return authorizer.mint_authorization(
            case_id="case_scope_valid",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_scope_valid",
            max_amount_in_cents=20000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_scope_valid",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_scope_valid",
            current_time=t0,
        )

    def test_tampered_customer_id_rejected(self, executor: ActionExecutor, valid_token: ActionAuthorization, mock_handler: MagicMock):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        req = ExecutionRequest(
            case_id="case_scope_valid",
            customer_id="cust_ATTACKER",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=20000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_scope_valid",
        )
        with pytest.raises(AuthorizationVerificationError, match="Customer mismatch"):
            executor.execute_action(request=req, token=valid_token, current_time=t0)
        mock_handler.assert_not_called()

    def test_tampered_currency_rejected(self, executor: ActionExecutor, valid_token: ActionAuthorization, mock_handler: MagicMock):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        req = ExecutionRequest(
            case_id="case_scope_valid",
            customer_id="cust_scope_valid",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=20000,
            currency="USD",  # Mismatched currency
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_scope_valid",
        )
        with pytest.raises(AuthorizationVerificationError, match="Currency mismatch"):
            executor.execute_action(request=req, token=valid_token, current_time=t0)
        mock_handler.assert_not_called()

    def test_amount_exceeding_authorized_bound_rejected(self, executor: ActionExecutor, valid_token: ActionAuthorization, mock_handler: MagicMock):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        req = ExecutionRequest(
            case_id="case_scope_valid",
            customer_id="cust_scope_valid",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=20001,  # 1 cent above max 20,000
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_scope_valid",
        )
        with pytest.raises(AuthorizationVerificationError, match="Requested amount .* exceeds authorized upper bound"):
            executor.execute_action(request=req, token=valid_token, current_time=t0)
        mock_handler.assert_not_called()

    def test_tampered_channel_rejected(self, executor: ActionExecutor, valid_token: ActionAuthorization, mock_handler: MagicMock):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        req = ExecutionRequest(
            case_id="case_scope_valid",
            customer_id="cust_scope_valid",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.SMS,  # Mismatched channel
            amount_in_cents=20000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_scope_valid",
        )
        with pytest.raises(AuthorizationVerificationError, match="Channel mismatch"):
            executor.execute_action(request=req, token=valid_token, current_time=t0)
        mock_handler.assert_not_called()

    def test_tampered_case_id_rejected(self, executor: ActionExecutor, valid_token: ActionAuthorization, mock_handler: MagicMock):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        req = ExecutionRequest(
            case_id="case_HIJACKED_999",
            customer_id="cust_scope_valid",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=20000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_scope_valid",
        )
        with pytest.raises(AuthorizationVerificationError, match="Scope mismatch: Request case_id"):
            executor.execute_action(request=req, token=valid_token, current_time=t0)
        mock_handler.assert_not_called()

    def test_tampered_action_type_rejected(self, executor: ActionExecutor, valid_token: ActionAuthorization, mock_handler: MagicMock):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        req = ExecutionRequest(
            case_id="case_scope_valid",
            customer_id="cust_scope_valid",
            action_type=ActionType.OFFER_PAYMENT_PLAN,  # Mismatched action type
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=20000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_scope_valid",
        )
        with pytest.raises(AuthorizationVerificationError, match="Scope mismatch: Request action_type"):
            executor.execute_action(request=req, token=valid_token, current_time=t0)
        mock_handler.assert_not_called()

    def test_tampered_idempotency_key_rejected(self, executor: ActionExecutor, valid_token: ActionAuthorization, mock_handler: MagicMock):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        req = ExecutionRequest(
            case_id="case_scope_valid",
            customer_id="cust_scope_valid",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=20000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="idemp_HIJACKED_KEY",
        )
        with pytest.raises(AuthorizationVerificationError, match="Scope mismatch: Request idempotency_key"):
            executor.execute_action(request=req, token=valid_token, current_time=t0)
        mock_handler.assert_not_called()
