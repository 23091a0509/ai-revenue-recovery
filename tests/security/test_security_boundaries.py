"""Security integration test suite verifying real process startup and configuration loading boundaries.

Architecture Invariants:
- INV-05: Strict MVP Sandbox Isolation (Config & Startup Layer — NOTE: Invariant remains NOT PROVEN until network-level transport firewall is implemented)
- INV-06: Zero Production Credentials in MVP (NOTE: Invariant remains NOT PROVEN until full key management & rotation is implemented)
"""

import os
import pytest
from src.revenue_recovery.foundation.config import (
    AppSettings,
    ConfigurationError,
    ProductionBoundaryViolationError,
    get_settings,
    load_settings_from_env,
    reset_cached_settings,
    scan_environment_for_forbidden_production_artifacts,
)


class TestStartupPathSecurityBoundaries:
    """Tests proving that forbidden production configurations cause the real startup loader to fail closed."""

    def setup_method(self):
        reset_cached_settings()

    def teardown_method(self):
        reset_cached_settings()

    @pytest.mark.parametrize("env_key,env_val", [
        ("STRIPE_SECRET_KEY", "sk_test_mock_1234567890"),
        ("stripe_secret_key", "sk_test_mock_1234567890"),
        ("Stripe_Secret_Key", "sk_test_mock_1234567890"),
        ("RAZORPAY_KEY_SECRET", "mock_key_secret_12345"),
        ("PAYPAL_CLIENT_SECRET", "mock_paypal_secret"),
        ("TWILIO_AUTH_TOKEN", "mock_twilio_token_12345"),
        ("twilio_auth_token", "mock_twilio_token_12345"),
        ("SENDGRID_API_KEY", "SG.mock_sendgrid_key"),
        ("MAILGUN_API_KEY", "key-mockmailgun12345"),
        ("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        ("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"),
        ("PROD_DATABASE_URL", "postgres://user:pass@prod-db.internal:5432/revenue"),
        ("PRODUCTION_HOST", "payments.prod.internal"),
        ("LIVE_GATEWAY_URL", "https://gateway.live.internal"),
        ("STAGING_ENDPOINT", "https://staging.internal"),
        ("CUSTOM_VARIABLE_CONTAINING_KEY", "sk_live_51ABC123XYZ456DEF789"),
        ("RANDOM_CONFIG", "pk_live_51ABC123XYZ456DEF789"),
        ("ANOTHER_VAR", "live_sec_abcdef123456789"),
        ("PROD_CONFIG_FLAG", "prod_secret_9988776655")
    ])
    def test_startup_loader_fails_closed_when_forbidden_env_present(
        self, monkeypatch: pytest.MonkeyPatch, env_key: str, env_val: str
    ):
        """
        Integration Requirement: The real startup path (load_settings_from_env / get_settings)
        must fail closed when any forbidden production variable or live key is present in os.environ.
        """
        monkeypatch.setenv("ENVIRONMENT", "sandbox")
        monkeypatch.setenv("AUTH_SIGNING_SECRET", "sandbox_explicit_valid_secret_key_32bytes")
        monkeypatch.setenv(env_key, env_val)

        # 1. Direct environment loader fails closed
        with pytest.raises(ProductionBoundaryViolationError):
            load_settings_from_env()

        # 2. Cached application startup getter fails closed
        with pytest.raises(ProductionBoundaryViolationError):
            get_settings()

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
    def test_startup_loader_rejects_host_tampering(
        self, monkeypatch: pytest.MonkeyPatch, host_trick: str
    ):
        """
        Integration Requirement: Non-sandbox URLs in os.environ cause startup to fail closed.
        """
        monkeypatch.setenv("ENVIRONMENT", "sandbox")
        monkeypatch.setenv("AUTH_SIGNING_SECRET", "sandbox_explicit_valid_secret_key_32bytes")
        monkeypatch.setenv("SANDBOX_PAYMENT_SIMULATOR_URL", host_trick)

        with pytest.raises(ProductionBoundaryViolationError):
            load_settings_from_env()

    def test_startup_singleton_caching_and_reset_lifecycle(self, monkeypatch: pytest.MonkeyPatch):
        """
        Lifecycle Requirement: `get_settings()` returns an immutable singleton,
        and `reset_cached_settings()` cleanly reloads on environment updates.
        """
        monkeypatch.setenv("ENVIRONMENT", "sandbox")
        monkeypatch.setenv("AUTH_SIGNING_SECRET", "sandbox_explicit_valid_secret_key_32bytes")
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")

        settings_1 = get_settings()
        settings_2 = get_settings()
        assert settings_1 is settings_2
        assert settings_1.log_level == "DEBUG"

        # Update environment and verify cached singleton is unchanged until reset
        monkeypatch.setenv("LOG_LEVEL", "WARNING")
        assert get_settings().log_level == "DEBUG"

        reset_cached_settings()
        settings_3 = get_settings()
        assert settings_3.log_level == "WARNING"
