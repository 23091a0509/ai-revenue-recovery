"""Unit tests for TICKET-01: Environment configuration and production safeguard validator.

Test Requirement Matrix:
1. Sandbox configuration is accepted.
2. Production payment endpoints are rejected.
3. Production messaging endpoints are rejected.
4. Production credentials are rejected.
5. Mixed sandbox/production configuration is rejected.
6. Missing/malformed required sandbox configuration fails safely.
7. Suspicious production-like configuration cannot silently pass.
8. Configuration immutability and tamper-resistance.
"""

import pytest
from pydantic import ValidationError

from src.revenue_recovery.foundation.config import (
    AppSettings,
    ConfigurationError,
    ProductionBoundaryViolationError,
    load_settings_from_env,
)


class TestConfigProductionSafeguards:
    """Requirement -> Threat -> Control -> Test -> Evidence mapping."""

    def test_valid_sandbox_configuration_accepted(self):
        """
        Requirement: Allow execution in valid local/sandbox environments.
        Threat: False rejection of legitimate developer sandbox environments.
        Control: Whitelisted localhost, 127.0.0.1, and sandbox-* hostnames with 'sandbox' mode.
        """
        config = load_settings_from_env({
            "ENVIRONMENT": "sandbox",
            "SANDBOX_PAYMENT_SIMULATOR_URL": "http://localhost:8001",
            "SANDBOX_MESSAGING_SIMULATOR_URL": "http://127.0.0.1:8002",
            "AUTH_SIGNING_SECRET": "local-test-secret",
            "TOKEN_EXPIRY_SECONDS": "300"
        })
        assert config.environment == "sandbox"
        assert config.sandbox_payment_simulator_url == "http://localhost:8001"
        assert config.sandbox_messaging_simulator_url == "http://127.0.0.1:8002"
        assert config.token_expiry_seconds == 300

    @pytest.mark.parametrize("prod_env", [
        "production",
        "PRODUCTION",
        "prod",
        "PROD",
        "live",
        "LIVE",
        "mainnet",
        "staging"
    ])
    def test_production_environment_mode_strictly_rejected(self, prod_env: str):
        """
        Requirement: Non-negotiable Rule 4 & 5 - MVP must remain isolated from production.
        Threat: Accidentally running the MVP code directly configured as production/live.
        Control: Fail-closed rejection if ENVIRONMENT is not strictly 'sandbox'.
        """
        with pytest.raises(ProductionBoundaryViolationError, match="Production boundary violation"):
            load_settings_from_env({"ENVIRONMENT": prod_env})

    @pytest.mark.parametrize("invalid_env", [
        "development",
        "qa",
        "custom",
        "testing_prod"
    ])
    def test_non_sandbox_arbitrary_environment_rejected(self, invalid_env: str):
        """
        Requirement: Only explicit 'sandbox' environment is accepted.
        Threat: Ambiguous or unauthorized environments bypassing sandbox controls.
        Control: ConfigurationError raised when environment is anything other than 'sandbox'.
        """
        with pytest.raises(ConfigurationError, match="Only 'sandbox' is permitted in MVP"):
            load_settings_from_env({"ENVIRONMENT": invalid_env})

    @pytest.mark.parametrize("prod_url", [
        "https://api.stripe.com/v1/charges",
        "https://api.razorpay.com/v1/payments",
        "https://api.paypal.com/v2/checkout/orders",
        "https://api.braintreegateway.com/merchants",
        "https://api.adyen.com/v68/payments",
        "https://api.squareup.com/v2/payments",
        "https://api.checkout.com/payments"
    ])
    def test_production_payment_endpoints_rejected(self, prod_url: str):
        """
        Requirement: Non-negotiable Rule 5 - No production payment endpoints in MVP.
        Threat: MVP accidentally sending real payment capture/charge requests to live gateways.
        Control: Blacklist of known payment gateways and whitelist of approved sandbox patterns.
        """
        with pytest.raises(ProductionBoundaryViolationError, match="Real provider endpoint detected|not a permitted sandbox target"):
            load_settings_from_env({
                "ENVIRONMENT": "sandbox",
                "SANDBOX_PAYMENT_SIMULATOR_URL": prod_url
            })

    @pytest.mark.parametrize("prod_msg_url", [
        "https://api.twilio.com/2010-04-01/Accounts",
        "https://api.sendgrid.com/v3/mail/send",
        "https://api.mailgun.net/v3",
        "https://graph.facebook.com/v17.0/messages",
        "https://api.whatsapp.com/v1/messages"
    ])
    def test_production_messaging_endpoints_rejected(self, prod_msg_url: str):
        """
        Requirement: Non-negotiable Rule 5 - No production messaging endpoints in MVP.
        Threat: MVP sending real recovery emails/SMS/WhatsApp messages to real customers.
        Control: Explicit domain blacklist and sandbox host whitelist.
        """
        with pytest.raises(ProductionBoundaryViolationError, match="Real provider endpoint detected|not a permitted sandbox target"):
            load_settings_from_env({
                "ENVIRONMENT": "sandbox",
                "SANDBOX_MESSAGING_SIMULATOR_URL": prod_msg_url
            })

    @pytest.mark.parametrize("live_key", [
        "sk_live_51ABC123XYZ456DEF789",
        "pk_live_51ABC123XYZ456DEF789",
        "rk_live_51ABC123XYZ456DEF789",
        "live_sec_abcdef123456789",
        "prod_secret_9988776655",
        "AKIAIOSFODNN7EXAMPLE"
    ])
    def test_production_credentials_rejected(self, live_key: str):
        """
        Requirement: Non-negotiable Rule 5 - No production credentials or secrets.
        Threat: Secret leak or live credential injection into sandbox process.
        Control: Regex pattern detection for live API key prefixes in secrets and across all fields.
        """
        with pytest.raises(ProductionBoundaryViolationError, match="Detected live/production credential format"):
            load_settings_from_env({
                "ENVIRONMENT": "sandbox",
                "AUTH_SIGNING_SECRET": live_key
            })

    def test_mixed_sandbox_and_production_configuration_rejected(self):
        """
        Requirement: Rejection of hybrid configurations attempting to sneak in production targets.
        Threat: Setting sandbox mode but configuring a production payment endpoint.
        Control: Independent validation of every configuration parameter before settings instantiation.
        """
        with pytest.raises(ProductionBoundaryViolationError):
            load_settings_from_env({
                "ENVIRONMENT": "sandbox",
                "SANDBOX_PAYMENT_SIMULATOR_URL": "https://api.stripe.com/v1",
                "SANDBOX_MESSAGING_SIMULATOR_URL": "http://localhost:8002"
            })

    @pytest.mark.parametrize("malformed_url", [
        "",
        "not_a_valid_url",
        "ftp://localhost:8001",
        "http://",
        "https://"
    ])
    def test_malformed_simulator_urls_fail_safely(self, malformed_url: str):
        """
        Requirement: Missing or malformed required URLs must fail closed.
        Threat: Silent fallback to undefined networking or bypass of egress checks.
        Control: Strict URL schema and structure validation.
        """
        with pytest.raises((ConfigurationError, ProductionBoundaryViolationError)):
            load_settings_from_env({
                "ENVIRONMENT": "sandbox",
                "SANDBOX_PAYMENT_SIMULATOR_URL": malformed_url
            })

    def test_suspicious_credential_in_any_field_rejected(self):
        """
        Requirement: Deep scan across all fields for live credentials.
        Threat: Placing a live secret into an unexpected field (e.g. log_level or llm_provider).
        Control: Model-level validator scanning all string values for production key signatures.
        """
        with pytest.raises(ProductionBoundaryViolationError, match="contains suspicious production-like credential format"):
            AppSettings(
                environment="sandbox",
                log_level="sk_live_1234567890abcdef",
                sandbox_payment_simulator_url="http://localhost:8001",
                sandbox_messaging_simulator_url="http://localhost:8002"
            )

    def test_settings_immutability_prevents_runtime_tampering(self):
        """
        Requirement: Configuration validation cannot be bypassed at runtime by in-memory mutation.
        Threat: Application code modifying settings object after validation to point to production.
        Control: Frozen Pydantic model (`frozen=True`) preventing attribute reassignment.
        """
        config = load_settings_from_env({
            "ENVIRONMENT": "sandbox",
            "SANDBOX_PAYMENT_SIMULATOR_URL": "http://localhost:8001"
        })
        with pytest.raises(ValidationError):
            # Attempt to bypass boundary at runtime
            config.environment = "production"  # type: ignore

        with pytest.raises(ValidationError):
            config.sandbox_payment_simulator_url = "https://api.stripe.com"  # type: ignore

    def test_extra_unrecognized_fields_forbidden(self):
        """
        Requirement: Strict schema enforcement.
        Threat: Injecting unauthorized configuration keys through environment overrides.
        Control: `extra="forbid"` on AppSettings.
        """
        with pytest.raises(ValidationError):
            AppSettings(
                environment="sandbox",
                unauthorized_override="danger"
            )
