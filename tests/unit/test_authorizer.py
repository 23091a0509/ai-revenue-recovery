"""Unit tests for Cryptographic Action Authorization token model, minter, and verifier (TICKET-05).

Architecture Baseline: Frozen Architecture Baseline v11.
Proves Rule 2 & Rule 3: The Executor acts only on valid, cryptographically signed,
bounded, and time-expiring Authorization tokens.
"""

from datetime import datetime, timedelta, timezone
import pytest
from pydantic import ValidationError

from src.revenue_recovery.foundation.config import (
    ConfigurationError,
    ProductionBoundaryViolationError,
)
from src.revenue_recovery.foundation.events import ActionChannel, ActionType
from src.revenue_recovery.safety import (
    ActionAuthorization,
    AuthorizationStatus,
    AuthorizationVerificationError,
    CryptographicAuthorizer,
    canonical_signing_string,
    validate_authorizer_signing_secret,
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
        """Proves Requirement 23: Authorization model remains immutable."""
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

    def test_extra_fields_rejected(self):
        """Proves Requirement 24: Extra unrecognized fields are rejected."""
        expires = datetime.now(timezone.utc) + timedelta(minutes=15)
        with pytest.raises(ValidationError):
            ActionAuthorization(
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
                unauthorized_bypass_field=True  # type: ignore
            )


class TestSigningSecretValidation:
    """Tests proving Requirement 13: Weak or production signing secrets are rejected."""

    @pytest.mark.parametrize("weak_secret", [
        "",
        "   ",
        "short",
        "1234567890",
        "sandbox-default-signing-secret-do-not-use-in-prod",
        "default_secret",
        "password12345678",
        "1234567890123456",
        "abcdefghijklmnop",
    ])
    def test_weak_signing_secret_rejected(self, weak_secret: str):
        with pytest.raises(ConfigurationError):
            validate_authorizer_signing_secret(weak_secret)

        with pytest.raises(ConfigurationError):
            CryptographicAuthorizer(signing_secret=weak_secret)

    @pytest.mark.parametrize("prod_key", [
        "sk_live_51ABC123XYZ456DEF789",
        "pk_live_51ABC123XYZ456DEF789",
        "rk_live_51ABC123XYZ456DEF789",
        "live_sec_abcdef123456789",
        "prod_secret_9988776655",
        "AKIAIOSFODNN7EXAMPLE"
    ])
    def test_production_credential_in_signing_secret_rejected(self, prod_key: str):
        with pytest.raises(ProductionBoundaryViolationError):
            validate_authorizer_signing_secret(prod_key)

        with pytest.raises(ProductionBoundaryViolationError):
            CryptographicAuthorizer(signing_secret=prod_key)


class TestCryptographicAuthorizerMintingAndVerification:
    """Tests for minting boundary, parameter tamper rejection, and bounds verification."""

    @pytest.fixture
    def authorizer(self) -> CryptographicAuthorizer:
        return CryptographicAuthorizer(signing_secret="sandbox-test-signing-secret-minimum-16-chars-safe")

    def test_minting_with_past_expiry_rejected(self, authorizer: CryptographicAuthorizer):
        """Proves Defect 2 fix: minting an already-expired token fails closed."""
        current_time = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        past_time = datetime(2026, 6, 1, 11, 59, 59, tzinfo=timezone.utc)

        with pytest.raises(ValueError, match="Token expiration must be strictly in the future"):
            authorizer.mint_authorization(
                case_id="case_001",
                action_type=ActionType.RETRY_CHARGE,
                customer_id="cust_999",
                max_amount_in_cents=25000,
                currency="INR",
                channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
                policy_version="policy_v1",
                decision_id="dec_001",
                expires_at=past_time,
                idempotency_key="idemp_001",
                current_time=current_time
            )

    def test_minting_with_exact_current_time_expiry_rejected(self, authorizer: CryptographicAuthorizer):
        """Proves Defect 2 fix: minting with expiry equal to current time fails closed."""
        current_time = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

        with pytest.raises(ValueError, match="Token expiration must be strictly in the future"):
            authorizer.mint_authorization(
                case_id="case_001",
                action_type=ActionType.RETRY_CHARGE,
                customer_id="cust_999",
                max_amount_in_cents=25000,
                currency="INR",
                channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
                policy_version="policy_v1",
                decision_id="dec_001",
                expires_at=current_time,
                idempotency_key="idemp_001",
                current_time=current_time
            )

    def test_minting_and_verifying_valid_future_token(self, authorizer: CryptographicAuthorizer):
        """Proves Requirement 16: Future authorization accepted."""
        current_time = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        expires = current_time + timedelta(minutes=10)

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
            idempotency_key="idemp_txn_001",
            current_time=current_time
        )

        assert len(token.signature) == 64
        assert authorizer.verify_authorization(
            token=token,
            expected_customer_id="cust_999",
            expected_currency="INR",
            requested_amount_in_cents=25000,
            expected_channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            current_time=current_time
        ) is True

    def test_signature_tampering_rejected(self, authorizer: CryptographicAuthorizer):
        """Proves Requirement 1: Signature tampering rejected."""
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = authorizer.mint_authorization(
            case_id="case_001", action_type=ActionType.RETRY_CHARGE, customer_id="cust_999",
            max_amount_in_cents=25000, currency="INR", channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1", decision_id="dec_001", expires_at=expires, idempotency_key="idemp_001"
        )
        forged = token.model_copy(update={"signature": "f" * 64})
        with pytest.raises(AuthorizationVerificationError, match="signature mismatch"):
            authorizer.verify_authorization(forged)

    def test_case_id_tampering_rejected(self, authorizer: CryptographicAuthorizer):
        """Proves Requirement 2: Case ID tampering rejected."""
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = authorizer.mint_authorization(
            case_id="case_001", action_type=ActionType.RETRY_CHARGE, customer_id="cust_999",
            max_amount_in_cents=25000, currency="INR", channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1", decision_id="dec_001", expires_at=expires, idempotency_key="idemp_001"
        )
        forged = token.model_copy(update={"case_id": "case_forged_999"})
        with pytest.raises(AuthorizationVerificationError, match="signature mismatch"):
            authorizer.verify_authorization(forged)

    def test_customer_id_tampering_rejected(self, authorizer: CryptographicAuthorizer):
        """Proves Requirement 3: Customer ID tampering rejected."""
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = authorizer.mint_authorization(
            case_id="case_001", action_type=ActionType.RETRY_CHARGE, customer_id="cust_999",
            max_amount_in_cents=25000, currency="INR", channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1", decision_id="dec_001", expires_at=expires, idempotency_key="idemp_001"
        )
        forged = token.model_copy(update={"customer_id": "cust_victim"})
        with pytest.raises(AuthorizationVerificationError, match="signature mismatch"):
            authorizer.verify_authorization(forged)

    def test_action_type_tampering_rejected(self, authorizer: CryptographicAuthorizer):
        """Proves Requirement 4: Action type tampering rejected."""
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = authorizer.mint_authorization(
            case_id="case_001", action_type=ActionType.RETRY_CHARGE, customer_id="cust_999",
            max_amount_in_cents=25000, currency="INR", channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1", decision_id="dec_001", expires_at=expires, idempotency_key="idemp_001"
        )
        forged = token.model_copy(update={"action_type": ActionType.OFFER_PAYMENT_PLAN})
        with pytest.raises(AuthorizationVerificationError, match="signature mismatch"):
            authorizer.verify_authorization(forged)

    def test_amount_tampering_rejected(self, authorizer: CryptographicAuthorizer):
        """Proves Requirement 5: Amount tampering rejected."""
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = authorizer.mint_authorization(
            case_id="case_001", action_type=ActionType.RETRY_CHARGE, customer_id="cust_999",
            max_amount_in_cents=5000, currency="INR", channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1", decision_id="dec_001", expires_at=expires, idempotency_key="idemp_001"
        )
        forged = token.model_copy(update={"max_amount_in_cents": 500000})
        with pytest.raises(AuthorizationVerificationError, match="signature mismatch"):
            authorizer.verify_authorization(forged)

    def test_currency_tampering_rejected(self, authorizer: CryptographicAuthorizer):
        """Proves Requirement 6: Currency tampering rejected."""
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = authorizer.mint_authorization(
            case_id="case_001", action_type=ActionType.RETRY_CHARGE, customer_id="cust_999",
            max_amount_in_cents=5000, currency="INR", channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1", decision_id="dec_001", expires_at=expires, idempotency_key="idemp_001"
        )
        forged = token.model_copy(update={"currency": "USD"})
        with pytest.raises(AuthorizationVerificationError, match="signature mismatch"):
            authorizer.verify_authorization(forged)

    def test_channel_tampering_rejected(self, authorizer: CryptographicAuthorizer):
        """Proves Requirement 7: Channel tampering rejected."""
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = authorizer.mint_authorization(
            case_id="case_001", action_type=ActionType.RETRY_CHARGE, customer_id="cust_999",
            max_amount_in_cents=5000, currency="INR", channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1", decision_id="dec_001", expires_at=expires, idempotency_key="idemp_001"
        )
        forged = token.model_copy(update={"channel": ActionChannel.EMAIL})
        with pytest.raises(AuthorizationVerificationError, match="signature mismatch"):
            authorizer.verify_authorization(forged)

    def test_policy_version_tampering_rejected(self, authorizer: CryptographicAuthorizer):
        """Proves Requirement 8: Policy version tampering rejected."""
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = authorizer.mint_authorization(
            case_id="case_001", action_type=ActionType.RETRY_CHARGE, customer_id="cust_999",
            max_amount_in_cents=5000, currency="INR", channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1", decision_id="dec_001", expires_at=expires, idempotency_key="idemp_001"
        )
        forged = token.model_copy(update={"policy_version": "policy_forged_v99"})
        with pytest.raises(AuthorizationVerificationError, match="signature mismatch"):
            authorizer.verify_authorization(forged)

    def test_decision_id_tampering_rejected(self, authorizer: CryptographicAuthorizer):
        """Proves Requirement 9: Decision ID tampering rejected."""
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = authorizer.mint_authorization(
            case_id="case_001", action_type=ActionType.RETRY_CHARGE, customer_id="cust_999",
            max_amount_in_cents=5000, currency="INR", channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1", decision_id="dec_001", expires_at=expires, idempotency_key="idemp_001"
        )
        forged = token.model_copy(update={"decision_id": "dec_forged_999"})
        with pytest.raises(AuthorizationVerificationError, match="signature mismatch"):
            authorizer.verify_authorization(forged)

    def test_expiry_tampering_rejected(self, authorizer: CryptographicAuthorizer):
        """Proves Requirement 10: Expiry tampering rejected."""
        current_time = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        expires = current_time + timedelta(minutes=5)
        token = authorizer.mint_authorization(
            case_id="case_001", action_type=ActionType.RETRY_CHARGE, customer_id="cust_999",
            max_amount_in_cents=5000, currency="INR", channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1", decision_id="dec_001", expires_at=expires, idempotency_key="idemp_001",
            current_time=current_time
        )
        extended_expiry = current_time + timedelta(days=30)
        forged = token.model_copy(update={"expires_at": extended_expiry})
        with pytest.raises(AuthorizationVerificationError, match="signature mismatch"):
            authorizer.verify_authorization(forged, current_time=current_time)

    def test_idempotency_key_tampering_rejected(self, authorizer: CryptographicAuthorizer):
        """Proves Requirement 11: Idempotency key tampering rejected."""
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = authorizer.mint_authorization(
            case_id="case_001", action_type=ActionType.RETRY_CHARGE, customer_id="cust_999",
            max_amount_in_cents=5000, currency="INR", channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1", decision_id="dec_001", expires_at=expires, idempotency_key="idemp_001"
        )
        forged = token.model_copy(update={"idempotency_key": "idemp_forged_999"})
        with pytest.raises(AuthorizationVerificationError, match="signature mismatch"):
            authorizer.verify_authorization(forged)

    def test_wrong_signing_secret_rejected(self):
        """Proves Requirement 12: Token minted with key A is rejected by verifier with key B."""
        authorizer_a = CryptographicAuthorizer(signing_secret="signing-secret-authorizer-a-minimum16")
        authorizer_b = CryptographicAuthorizer(signing_secret="signing-secret-authorizer-b-minimum16")

        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = authorizer_a.mint_authorization(
            case_id="case_001", action_type=ActionType.RETRY_CHARGE, customer_id="cust_999",
            max_amount_in_cents=5000, currency="INR", channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1", decision_id="dec_001", expires_at=expires, idempotency_key="idemp_001"
        )

        with pytest.raises(AuthorizationVerificationError, match="signature mismatch"):
            authorizer_b.verify_authorization(token)

    def test_expired_authorization_rejected(self, authorizer: CryptographicAuthorizer):
        """Proves Requirement 14: Expired authorization token is rejected at verification."""
        t0 = datetime(2026, 6, 1, 10, 0, 0, tzinfo=timezone.utc)
        expires = t0 + timedelta(minutes=15)
        token = authorizer.mint_authorization(
            case_id="case_001", action_type=ActionType.RETRY_CHARGE, customer_id="cust_999",
            max_amount_in_cents=5000, currency="INR", channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1", decision_id="dec_001", expires_at=expires, idempotency_key="idemp_001",
            current_time=t0
        )

        t_after = t0 + timedelta(minutes=16)
        with pytest.raises(AuthorizationVerificationError, match="Token has expired"):
            authorizer.verify_authorization(token, current_time=t_after)

    def test_exact_expiry_authorization_rejected(self, authorizer: CryptographicAuthorizer):
        """Proves Requirement 15: Token evaluated at exact expiry timestamp is rejected."""
        t0 = datetime(2026, 6, 1, 10, 0, 0, tzinfo=timezone.utc)
        expires = t0 + timedelta(minutes=15)
        token = authorizer.mint_authorization(
            case_id="case_001", action_type=ActionType.RETRY_CHARGE, customer_id="cust_999",
            max_amount_in_cents=5000, currency="INR", channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1", decision_id="dec_001", expires_at=expires, idempotency_key="idemp_001",
            current_time=t0
        )

        with pytest.raises(AuthorizationVerificationError, match="Token has expired"):
            authorizer.verify_authorization(token, current_time=expires)

    def test_customer_mismatch_rejected(self, authorizer: CryptographicAuthorizer):
        """Proves Requirement 17: Customer mismatch rejected."""
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = authorizer.mint_authorization(
            case_id="case_001", action_type=ActionType.RETRY_CHARGE, customer_id="cust_999",
            max_amount_in_cents=10000, currency="INR", channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1", decision_id="dec_001", expires_at=expires, idempotency_key="idemp_001"
        )
        with pytest.raises(AuthorizationVerificationError, match="Customer mismatch"):
            authorizer.verify_authorization(token, expected_customer_id="wrong_customer")

    def test_currency_mismatch_rejected(self, authorizer: CryptographicAuthorizer):
        """Proves Requirement 18: Currency mismatch rejected."""
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = authorizer.mint_authorization(
            case_id="case_001", action_type=ActionType.RETRY_CHARGE, customer_id="cust_999",
            max_amount_in_cents=10000, currency="INR", channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1", decision_id="dec_001", expires_at=expires, idempotency_key="idemp_001"
        )
        with pytest.raises(AuthorizationVerificationError, match="Currency mismatch"):
            authorizer.verify_authorization(token, expected_currency="USD")

    def test_amount_above_authorized_bound_rejected(self, authorizer: CryptographicAuthorizer):
        """Proves Requirement 19: Amount above authorized upper bound rejected."""
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = authorizer.mint_authorization(
            case_id="case_001", action_type=ActionType.RETRY_CHARGE, customer_id="cust_999",
            max_amount_in_cents=10000, currency="INR", channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1", decision_id="dec_001", expires_at=expires, idempotency_key="idemp_001"
        )
        with pytest.raises(AuthorizationVerificationError, match="exceeds authorized upper bound"):
            authorizer.verify_authorization(token, requested_amount_in_cents=10001)

    @pytest.mark.parametrize("invalid_amount", [0, -1, -5000])
    def test_zero_or_negative_requested_amount_rejected(self, authorizer: CryptographicAuthorizer, invalid_amount: int):
        """Proves Requirement 20: Zero or negative requested amount rejected."""
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = authorizer.mint_authorization(
            case_id="case_001", action_type=ActionType.RETRY_CHARGE, customer_id="cust_999",
            max_amount_in_cents=10000, currency="INR", channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1", decision_id="dec_001", expires_at=expires, idempotency_key="idemp_001"
        )
        with pytest.raises(AuthorizationVerificationError, match="Requested execution amount must be positive"):
            authorizer.verify_authorization(token, requested_amount_in_cents=invalid_amount)

    def test_channel_mismatch_rejected(self, authorizer: CryptographicAuthorizer):
        """Proves Requirement 21: Channel mismatch rejected."""
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = authorizer.mint_authorization(
            case_id="case_001", action_type=ActionType.RETRY_CHARGE, customer_id="cust_999",
            max_amount_in_cents=10000, currency="INR", channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1", decision_id="dec_001", expires_at=expires, idempotency_key="idemp_001"
        )
        with pytest.raises(AuthorizationVerificationError, match="Channel mismatch"):
            authorizer.verify_authorization(token, expected_channel=ActionChannel.SMS)

    @pytest.mark.parametrize("bad_status", [
        AuthorizationStatus.CONSUMED,
        AuthorizationStatus.EXPIRED,
        AuthorizationStatus.REVOKED
    ])
    def test_non_issued_status_rejected(self, authorizer: CryptographicAuthorizer, bad_status: AuthorizationStatus):
        """Proves Requirement 22: Non-ISSUED status rejected."""
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = authorizer.mint_authorization(
            case_id="case_001", action_type=ActionType.RETRY_CHARGE, customer_id="cust_999",
            max_amount_in_cents=10000, currency="INR", channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="policy_v1", decision_id="dec_001", expires_at=expires, idempotency_key="idemp_001"
        )
        non_issued = token.model_copy(update={"status": bad_status})
        with pytest.raises(AuthorizationVerificationError, match="Token status is invalid"):
            authorizer.verify_authorization(non_issued)

    def test_public_safety_exports(self):
        """Proves all safety public symbols are exported."""
        import src.revenue_recovery.safety as safety
        assert hasattr(safety, "ActionAuthorization")
        assert hasattr(safety, "AuthorizationStatus")
        assert hasattr(safety, "AuthorizationVerificationError")
        assert hasattr(safety, "CryptographicAuthorizer")
        assert hasattr(safety, "canonical_signing_string")
        assert hasattr(safety, "validate_authorizer_signing_secret")
