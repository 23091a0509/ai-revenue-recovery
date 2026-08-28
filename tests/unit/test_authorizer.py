"""Unit tests for Cryptographic Action Authorization token model, minter, and verifier (TICKET-05).

Architecture Baseline: Frozen Architecture Baseline v11.
Proves Rule 2 & Rule 3: The Executor acts only on valid, cryptographically signed,
bounded, and time-expiring Authorization tokens.
"""

from datetime import datetime, timedelta, timezone
import pytest
from pydantic import ValidationError

from src.revenue_recovery.foundation.events import ActionChannel, ActionType
from src.revenue_recovery.safety import (
    ActionAuthorization,
    AuthorizationStatus,
    AuthorizationVerificationError,
    CryptographicAuthorizer,
    canonical_signing_string,
)


class TestActionAuthorizationModel:
    """Tests for ActionAuthorization model schema, immutability, and validation."""

    def test_valid_action_authorization_construction(self):
        expires = datetime.now(timezone.utc) + timedelta(minutes=15)
        auth = ActionAuthorization(
            case_id="case_123",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_456",
            max_amount_in_cents=10000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_789",
            expires_at=expires,
            idempotency_key="idemp_abc",
            signature="a" * 64,
            status=AuthorizationStatus.ISSUED
        )
        assert auth.case_id == "case_123"
        assert auth.max_amount_in_cents == 10000
        assert auth.currency == "INR"
        assert auth.status == AuthorizationStatus.ISSUED

    def test_invalid_negative_or_zero_amount_rejected(self):
        expires = datetime.now(timezone.utc) + timedelta(minutes=15)
        with pytest.raises(ValidationError):
            ActionAuthorization(
                case_id="case_123",
                action_type=ActionType.RETRY_CHARGE,
                customer_id="cust_456",
                max_amount_in_cents=0,
                currency="INR",
                channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
                policy_version="v1.0",
                decision_id="dec_789",
                expires_at=expires,
                idempotency_key="idemp_abc",
                signature="a" * 64
            )

    def test_invalid_signature_format_rejected(self):
        expires = datetime.now(timezone.utc) + timedelta(minutes=15)
        with pytest.raises(ValidationError):
            ActionAuthorization(
                case_id="case_123",
                action_type=ActionType.RETRY_CHARGE,
                customer_id="cust_456",
                max_amount_in_cents=5000,
                currency="INR",
                channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
                policy_version="v1.0",
                decision_id="dec_789",
                expires_at=expires,
                idempotency_key="idemp_abc",
                signature="invalid_non_hex_or_short_sig"
            )

    def test_immutability_prevents_tampering(self):
        expires = datetime.now(timezone.utc) + timedelta(minutes=15)
        auth = ActionAuthorization(
            case_id="case_123",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_456",
            max_amount_in_cents=10000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_789",
            expires_at=expires,
            idempotency_key="idemp_abc",
            signature="a" * 64
        )
        with pytest.raises(ValidationError):
            auth.max_amount_in_cents = 999999  # type: ignore


class TestCryptographicAuthorizer:
    """Tests for token minting, cryptographic verification, and parameter bounding."""

    @pytest.fixture
    def authorizer(self) -> CryptographicAuthorizer:
        return CryptographicAuthorizer(signing_secret="sandbox-test-signing-secret-minimum-16-chars")

    def test_mint_and_verify_valid_token(self, authorizer: CryptographicAuthorizer):
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = authorizer.mint_authorization(
            case_id="case_001",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_999",
            max_amount_in_cents=25000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1",
            decision_id="dec_001",
            expires_at=expires,
            idempotency_key="idemp_txn_001"
        )

        assert token.signature is not None
        assert len(token.signature) == 64

        # Verification succeeds with valid parameters
        is_valid = authorizer.verify_authorization(
            token=token,
            expected_customer_id="cust_999",
            expected_currency="INR",
            requested_amount_in_cents=25000,
            expected_channel=ActionChannel.DIRECT_PAYMENT_GATEWAY
        )
        assert is_valid is True

    def test_tampered_signature_fails_verification(self, authorizer: CryptographicAuthorizer):
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = authorizer.mint_authorization(
            case_id="case_001",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_999",
            max_amount_in_cents=25000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1",
            decision_id="dec_001",
            expires_at=expires,
            idempotency_key="idemp_txn_001"
        )

        # Create a forged token with an altered signature
        forged_token = ActionAuthorization(
            authorization_id=token.authorization_id,
            case_id=token.case_id,
            action_type=token.action_type,
            customer_id=token.customer_id,
            max_amount_in_cents=token.max_amount_in_cents,
            currency=token.currency,
            channel=token.channel,
            policy_version=token.policy_version,
            decision_id=token.decision_id,
            expires_at=token.expires_at,
            idempotency_key=token.idempotency_key,
            signature="f" * 64
        )

        with pytest.raises(AuthorizationVerificationError, match="Cryptographic signature mismatch"):
            authorizer.verify_authorization(forged_token)

    def test_tampered_amount_fails_verification(self, authorizer: CryptographicAuthorizer):
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = authorizer.mint_authorization(
            case_id="case_001",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_999",
            max_amount_in_cents=5000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1",
            decision_id="dec_001",
            expires_at=expires,
            idempotency_key="idemp_txn_001"
        )

        # An attacker attempts to forge higher amount under original signature
        forged_token = ActionAuthorization(
            authorization_id=token.authorization_id,
            case_id=token.case_id,
            action_type=token.action_type,
            customer_id=token.customer_id,
            max_amount_in_cents=500000,  # 100x increase
            currency=token.currency,
            channel=token.channel,
            policy_version=token.policy_version,
            decision_id=token.decision_id,
            expires_at=token.expires_at,
            idempotency_key=token.idempotency_key,
            signature=token.signature  # Original signature fails
        )

        with pytest.raises(AuthorizationVerificationError, match="Cryptographic signature mismatch"):
            authorizer.verify_authorization(forged_token)

    def test_expired_token_fails_verification(self, authorizer: CryptographicAuthorizer):
        past_time = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
        token = authorizer.mint_authorization(
            case_id="case_001",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_999",
            max_amount_in_cents=5000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1",
            decision_id="dec_001",
            expires_at=past_time,
            idempotency_key="idemp_txn_001"
        )

        current_time = datetime(2026, 1, 1, 10, 15, 0, tzinfo=timezone.utc)
        with pytest.raises(AuthorizationVerificationError, match="Token has expired"):
            authorizer.verify_authorization(token, current_time=current_time)

    def test_requested_amount_exceeding_bound_fails_verification(self, authorizer: CryptographicAuthorizer):
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = authorizer.mint_authorization(
            case_id="case_001",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_999",
            max_amount_in_cents=10000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1",
            decision_id="dec_001",
            expires_at=expires,
            idempotency_key="idemp_txn_001"
        )

        with pytest.raises(AuthorizationVerificationError, match="exceeds authorized upper bound"):
            authorizer.verify_authorization(token, requested_amount_in_cents=10001)

    def test_customer_or_currency_or_channel_mismatch_fails(self, authorizer: CryptographicAuthorizer):
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = authorizer.mint_authorization(
            case_id="case_001",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_999",
            max_amount_in_cents=10000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1",
            decision_id="dec_001",
            expires_at=expires,
            idempotency_key="idemp_txn_001"
        )

        with pytest.raises(AuthorizationVerificationError, match="Customer mismatch"):
            authorizer.verify_authorization(token, expected_customer_id="different_customer")

        with pytest.raises(AuthorizationVerificationError, match="Currency mismatch"):
            authorizer.verify_authorization(token, expected_currency="USD")

        with pytest.raises(AuthorizationVerificationError, match="Channel mismatch"):
            authorizer.verify_authorization(token, expected_channel=ActionChannel.SMS)

    def test_non_issued_status_fails_verification(self, authorizer: CryptographicAuthorizer):
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = authorizer.mint_authorization(
            case_id="case_001",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_999",
            max_amount_in_cents=10000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1",
            decision_id="dec_001",
            expires_at=expires,
            idempotency_key="idemp_txn_001"
        )

        consumed_token = ActionAuthorization(
            authorization_id=token.authorization_id,
            case_id=token.case_id,
            action_type=token.action_type,
            customer_id=token.customer_id,
            max_amount_in_cents=token.max_amount_in_cents,
            currency=token.currency,
            channel=token.channel,
            policy_version=token.policy_version,
            decision_id=token.decision_id,
            expires_at=token.expires_at,
            idempotency_key=token.idempotency_key,
            signature=token.signature,
            status=AuthorizationStatus.CONSUMED
        )

        with pytest.raises(AuthorizationVerificationError, match="Token status is invalid"):
            authorizer.verify_authorization(consumed_token)

    def test_public_safety_exports(self):
        import src.revenue_recovery.safety as safety
        assert hasattr(safety, "ActionAuthorization")
        assert hasattr(safety, "AuthorizationStatus")
        assert hasattr(safety, "AuthorizationVerificationError")
        assert hasattr(safety, "CryptographicAuthorizer")
        assert hasattr(safety, "canonical_signing_string")
