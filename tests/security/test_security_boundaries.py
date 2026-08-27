"""Security tests for production boundary enforcement, credential leakage prevention, and URL parsing attacks.

Architecture Invariants:
- INV-05: Strict MVP Sandbox Isolation (Config / Boundary Layer)
- INV-06: Zero Production Credentials in MVP
"""

import pytest
from src.revenue_recovery.foundation.config import (
    AppSettings,
    ConfigurationError,
    ProductionBoundaryViolationError,
    load_settings_from_env,
    scan_environment_for_forbidden_production_artifacts,
)


class TestSecurityBoundaries:
    """Rigorous security tests for production isolation and credential protections."""

    @pytest.mark.parametrize("payload", [
        {"STRIPE_SECRET_KEY": "sk_live_1234567890abcdef"},
        {"RAZORPAY_SECRET": "live_secret_998877665544"},
        {"TWILIO_AUTH_TOKEN": "0123456789abcdef0123456789abcdef"},
        {"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
        {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"},
        {"PROD_DATABASE_URL": "postgresql://postgres:secret@db.prod.internal:5432/app"},
        {"PRODUCTION_PAYMENTS_URL": "https://api.stripe.com"},
        {"LIVE_PAYMENTS_ENDPOINT": "https://api.razorpay.com"},
        {"STAGING_GATEWAY": "https://gateway.staging.internal"}
    ])
    def test_environment_scanner_blocks_all_production_variables(self, payload: dict):
        """
        Security property: The environment scanner halts execution if any production-related
        environment variable or live credential signature exists in the process environment.
        """
        with pytest.raises(ProductionBoundaryViolationError):
            scan_environment_for_forbidden_production_artifacts(payload)

    @pytest.mark.parametrize("host_trick", [
        "http://api.stripe.com",
        "https://api.stripe.com",
        "http://api.stripe.com:80",
        "https://api.stripe.com:443",
        "https://API.STRIPE.COM/v1/charges",
        "https://api.stripe.com./v1",
        "http://localhost@api.stripe.com/v1",
        "http://user:password@localhost:8001",
        "http://evil.com/sandbox-simulator",
        "http://sandbox-simulator.evil.com",
        "http://93.184.216.34:8001",
        "http://1.1.1.1:8001",
        "http://8.8.8.8:8001",
        "http://[2001:db8::1]:8001",
        "http://attacker.com/localhost",
    ])
    def test_simulator_endpoint_security_filter(self, host_trick: str):
        """
        Security property: Non-sandbox, non-loopback, deceptive, and production endpoints
        are unconditionally rejected.
        """
        with pytest.raises(ProductionBoundaryViolationError):
            load_settings_from_env({
                "ENVIRONMENT": "sandbox",
                "AUTH_SIGNING_SECRET": "sandbox_valid_test_secret_32bytes_min",
                "SANDBOX_PAYMENT_SIMULATOR_URL": host_trick
            })

    @pytest.mark.parametrize("weak_secret", [
        "short",
        "1234567890",
        "sandbox-default-signing-secret-do-not-use-in-prod",
        "default_secret",
        "change_this_secret",
        "password12345678"
    ])
    def test_signing_secret_entropy_and_default_prevention(self, weak_secret: str):
        """
        Security property: Weak, static, or short signing secrets cannot be used
        as authorization signing keys.
        """
        with pytest.raises(ConfigurationError):
            AppSettings(
                environment="sandbox",
                auth_signing_secret=weak_secret,
                sandbox_payment_simulator_url="http://localhost:8001",
                sandbox_messaging_simulator_url="http://localhost:8002"
            )
