"""Cryptographic Action Authorization token model, minter, and verifier.

Architecture Baseline: Frozen Architecture Baseline v11.
Enforces Rule 2 & Rule 3: The Executor acts only on valid, cryptographically signed,
bounded, and time-expiring Authorization tokens.
"""

from datetime import datetime, timezone
from enum import Enum
import hmac
import hashlib
from typing import Any
import uuid
from pydantic import Field, field_validator

from src.revenue_recovery.foundation.config import get_settings
from src.revenue_recovery.foundation.events import (
    ActionChannel,
    ActionType,
    ImmutableBaseModel,
)


class AuthorizationStatus(str, Enum):
    """Lifecycle status for an ActionAuthorization token."""
    ISSUED = "ISSUED"
    CONSUMED = "CONSUMED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class AuthorizationVerificationError(Exception):
    """Raised when an authorization token fails signature, bounds, or expiry verification."""
    pass


def canonical_signing_string(
    authorization_id: str,
    case_id: str,
    action_type: str,
    customer_id: str,
    max_amount_in_cents: int,
    currency: str,
    channel: str,
    policy_version: str,
    decision_id: str,
    expires_at: datetime,
    idempotency_key: str
) -> str:
    """
    Constructs a deterministic canonical string representation of authorization parameters for signing.
    """
    expires_iso = expires_at.isoformat()
    return (
        f"AUTH_V1|{authorization_id}|{case_id}|{action_type}|{customer_id}|"
        f"{max_amount_in_cents}|{currency.upper()}|{channel}|{policy_version}|"
        f"{decision_id}|{expires_iso}|{idempotency_key}"
    )


class ActionAuthorization(ImmutableBaseModel):
    """
    Immutable, cryptographically signed security token authorizing a bounded recovery action.
    """
    authorization_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str = Field(min_length=1)
    action_type: ActionType
    customer_id: str = Field(min_length=1)
    max_amount_in_cents: int = Field(gt=0, description="Upper bound on monetary recovery attempt in minor units")
    currency: str = Field(min_length=3, max_length=3)
    channel: ActionChannel
    policy_version: str = Field(min_length=1)
    decision_id: str = Field(min_length=1)
    expires_at: datetime
    idempotency_key: str = Field(min_length=1)
    signature: str = Field(min_length=64, max_length=64, description="HMAC-SHA256 hex digest signature")
    status: AuthorizationStatus = Field(default=AuthorizationStatus.ISSUED)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("currency")
    @classmethod
    def validate_currency(cls, v: str) -> str:
        v_upper = v.upper()
        if not v_upper.isalpha() or len(v_upper) != 3:
            raise ValueError("Currency must be a 3-letter ISO code")
        return v_upper

    @field_validator("signature")
    @classmethod
    def validate_signature_format(cls, v: str) -> str:
        v_lower = v.lower()
        if len(v_lower) != 64 or not all(c in "0123456789abcdef" for c in v_lower):
            raise ValueError("Signature must be a 64-character lowercase hex string")
        return v_lower


class CryptographicAuthorizer:
    """
    Service responsible for minting and verifying cryptographically signed ActionAuthorization tokens.
    """

    def __init__(self, signing_secret: str | None = None) -> None:
        if signing_secret is not None:
            self._signing_secret = signing_secret.encode("utf-8")
        else:
            settings = get_settings()
            self._signing_secret = settings.signing_secret.get_secret_value().encode("utf-8")

    def _compute_signature(self, canonical_str: str) -> str:
        """Computes HMAC-SHA256 signature over the canonical authorization string."""
        return hmac.new(self._signing_secret, canonical_str.encode("utf-8"), hashlib.sha256).hexdigest()

    def mint_authorization(
        self,
        case_id: str,
        action_type: ActionType,
        customer_id: str,
        max_amount_in_cents: int,
        currency: str,
        channel: ActionChannel,
        policy_version: str,
        decision_id: str,
        expires_at: datetime,
        idempotency_key: str,
        authorization_id: str | None = None
    ) -> ActionAuthorization:
        """
        Mints a new, cryptographically signed ActionAuthorization token.
        """
        auth_id = authorization_id or str(uuid.uuid4())
        action_type_val = action_type.value if hasattr(action_type, "value") else str(action_type)
        channel_val = channel.value if hasattr(channel, "value") else str(channel)

        canonical_str = canonical_signing_string(
            authorization_id=auth_id,
            case_id=case_id,
            action_type=action_type_val,
            customer_id=customer_id,
            max_amount_in_cents=max_amount_in_cents,
            currency=currency,
            channel=channel_val,
            policy_version=policy_version,
            decision_id=decision_id,
            expires_at=expires_at,
            idempotency_key=idempotency_key
        )
        signature = self._compute_signature(canonical_str)

        return ActionAuthorization(
            authorization_id=auth_id,
            case_id=case_id,
            action_type=action_type,
            customer_id=customer_id,
            max_amount_in_cents=max_amount_in_cents,
            currency=currency,
            channel=channel,
            policy_version=policy_version,
            decision_id=decision_id,
            expires_at=expires_at,
            idempotency_key=idempotency_key,
            signature=signature,
            status=AuthorizationStatus.ISSUED
        )

    def verify_authorization(
        self,
        token: ActionAuthorization,
        expected_customer_id: str | None = None,
        expected_currency: str | None = None,
        requested_amount_in_cents: int | None = None,
        expected_channel: ActionChannel | None = None,
        current_time: datetime | None = None
    ) -> bool:
        """
        Cryptographically verifies the authenticity, time-bounding, and parameter bounds of an ActionAuthorization token.
        Raises AuthorizationVerificationError if any check fails.
        """
        status_val = token.status.value if hasattr(token.status, "value") else str(token.status)
        action_type_val = token.action_type.value if hasattr(token.action_type, "value") else str(token.action_type)
        channel_val = token.channel.value if hasattr(token.channel, "value") else str(token.channel)

        # 1. Verify Status
        if status_val != AuthorizationStatus.ISSUED.value:
            raise AuthorizationVerificationError(
                f"Token status is invalid: expected '{AuthorizationStatus.ISSUED.value}', found '{status_val}'"
            )

        # 2. Verify Signature Integrity
        canonical_str = canonical_signing_string(
            authorization_id=token.authorization_id,
            case_id=token.case_id,
            action_type=action_type_val,
            customer_id=token.customer_id,
            max_amount_in_cents=token.max_amount_in_cents,
            currency=token.currency,
            channel=channel_val,
            policy_version=token.policy_version,
            decision_id=token.decision_id,
            expires_at=token.expires_at,
            idempotency_key=token.idempotency_key
        )
        expected_signature = self._compute_signature(canonical_str)

        if not hmac.compare_digest(expected_signature, token.signature):
            raise AuthorizationVerificationError(
                "Cryptographic signature mismatch: token parameters have been tampered with"
            )

        # 3. Verify Time-Bounding (Expiration)
        now = current_time or datetime.now(timezone.utc)
        if token.expires_at <= now:
            raise AuthorizationVerificationError(
                f"Token has expired at {token.expires_at.isoformat()} (current time: {now.isoformat()})"
            )

        # 4. Verify Customer Identity
        if expected_customer_id is not None and token.customer_id != expected_customer_id:
            raise AuthorizationVerificationError(
                f"Customer mismatch: token is bound to customer '{token.customer_id}', requested '{expected_customer_id}'"
            )

        # 5. Verify Currency
        if expected_currency is not None and token.currency != expected_currency.upper():
            raise AuthorizationVerificationError(
                f"Currency mismatch: token is bound to '{token.currency}', requested '{expected_currency.upper()}'"
            )

        # 6. Verify Monetary Upper Bound
        if requested_amount_in_cents is not None:
            if requested_amount_in_cents > token.max_amount_in_cents:
                raise AuthorizationVerificationError(
                    f"Requested amount ({requested_amount_in_cents}) exceeds authorized upper bound ({token.max_amount_in_cents})"
                )
            if requested_amount_in_cents <= 0:
                raise AuthorizationVerificationError("Requested execution amount must be positive")

        # 7. Verify Channel
        if expected_channel is not None:
            expected_channel_val = expected_channel.value if hasattr(expected_channel, "value") else str(expected_channel)
            if channel_val != expected_channel_val:
                raise AuthorizationVerificationError(
                    f"Channel mismatch: token is bound to '{channel_val}', requested '{expected_channel_val}'"
                )

        return True
