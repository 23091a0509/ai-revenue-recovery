"""Unit and adversarial tests for TICKET-01: Environment configuration and production safeguard validator.

Test Requirement Matrix:
1. Sandbox configuration is accepted.
2. Production payment and messaging endpoints are rejected across case variations, ports, and aliases.
3. Production credentials and keys are rejected across all fields and environment variables.
4. Unauthorized production-related environment variables cannot silently exist in the environment.
5. Public and non-loopback IP addresses are rejected.
6. URL userinfo tricks, trailing-dot bypasses, and deceptive hostname tricks are rejected.
7. Weak, empty, or static default signing secrets fail closed and cannot become authorization credentials.
8. Immutability prevents runtime tampering.
"""

import pytest
from pydantic import ValidationError

from src.revenue_recovery.foundation.config import (
    AppSettings,
    ConfigurationError,
    ProductionBoundaryViolationError,
    generate_ephemeral_sandbox_signing_secret,
    load_settings_from_env,
    scan_environment_for_forbidden_production_artifacts,
)


class TestConfigProductionSafeguards:
    """Requirement -> Threat -> Control -> Test -> Evidence mapping."""

    def test_valid_sandbox_configuration_accepted(self):
        """
        Requirement: Allow execution in valid local/sandbox environments.
        Threat: False rejection of legitimate developer sandbox environments.
        Control: Whitelisted localhost, 127.0.0.1, [::1], and sandbox-* hostnames with 'sandbox' mode.
        """
        config = load_settings_from_env({
            "ENVIRONMENT": "sandbox",
            "SANDBOX_PAYMENT_SIMULATOR_URL": "http://localhost:8001",
            "SANDBOX_MESSAGING_SIMULATOR_URL": "http://127.0.0.1:8002",
            "AUTH_SIGNING_SECRET": "sandbox_explicit_valid_secret_key_32bytes",
            "TOKEN_EXPIRY_SECONDS": "300"
        })
        assert config.environment == "sandbox"
        assert config.sandbox_payment_simulator_url == "http://localhost:8001"
        assert config.sandbox_messaging_simulator_url == "http://127.0.0.1:8002"
        assert config.token_expiry_seconds == 300

    def test_ipv6_loopback_accepted(self):
        """
        Requirement: Support IPv6 loopback [::1] in sandbox.
        Control: ipaddress loopback validation.
        """
        config = load_settings_from_env({
            "ENVIRONMENT": "sandbox",
            "SANDBOX_PAYMENT_SIMULATOR_URL": "http://[::1]:8001",
            "AUTH_SIGNING_SECRET": "sandbox_explicit_valid_secret_key_32bytes"
        })
        assert "[::1]" in config.sandbox_payment_simulator_url

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
        Threat: Running the MVP code configured as production/live.
        Control: Fail-closed rejection if ENVIRONMENT is not strictly 'sandbox'.
        """
        with pytest.raises(ProductionBoundaryViolationError, match="Production boundary violation"):
            load_settings_from_env({
                "ENVIRONMENT": prod_env,
                "AUTH_SIGNING_SECRET": "sandbox_explicit_valid_secret_key_32bytes"
            })

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
            load_settings_from_env({
                "ENVIRONMENT": invalid_env,
                "AUTH_SIGNING_SECRET": "sandbox_explicit_valid_secret_key_32bytes"
            })

    @pytest.mark.parametrize("prod_url", [
        "https://api.stripe.com/v1/charges",
        "https://API.STRIPE.COM/v1/charges",
        "https://api.stripe.com./v1/charges",
        "https://api.stripe.com:443/v1/charges",
        "https://api.razorpay.com/v1/payments",
        "https://API.RAZORPAY.COM/v1/payments",
        "https://api.paypal.com/v2/checkout/orders",
        "https://api.braintreegateway.com/merchants",
        "https://api.adyen.com/v68/payments",
        "https://api.squareup.com/v2/payments",
        "https://api.checkout.com/payments"
    ])
    def test_production_payment_endpoints_rejected(self, prod_url: str):
        """
        Requirement: Non-negotiable Rule 5 - No production payment endpoints in MVP.
        Threat: MVP connecting to live payment gateways via case, port, or trailing-dot variants.
        Control: Normalized domain check and sandbox pattern whitelist.
        """
        with pytest.raises(ProductionBoundaryViolationError, match="Real provider endpoint detected|not a permitted sandbox target"):
            load_settings_from_env({
                "ENVIRONMENT": "sandbox",
                "SANDBOX_PAYMENT_SIMULATOR_URL": prod_url,
                "AUTH_SIGNING_SECRET": "sandbox_explicit_valid_secret_key_32bytes"
            })

    @pytest.mark.parametrize("prod_msg_url", [
        "https://api.twilio.com/2010-04-01/Accounts",
        "https://API.TWILIO.COM/2010-04-01/Accounts",
        "https://api.sendgrid.com/v3/mail/send",
        "https://api.mailgun.net/v3",
        "https://graph.facebook.com/v17.0/messages",
        "https://api.whatsapp.com/v1/messages"
    ])
    def test_production_messaging_endpoints_rejected(self, prod_msg_url: str):
        """
        Requirement: Non-negotiable Rule 5 - No production messaging endpoints in MVP.
        Threat: MVP sending real recovery communications to customers.
        Control: Explicit domain blacklist and sandbox host whitelist.
        """
        with pytest.raises(ProductionBoundaryViolationError, match="Real provider endpoint detected|not a permitted sandbox target"):
            load_settings_from_env({
                "ENVIRONMENT": "sandbox",
                "SANDBOX_MESSAGING_SIMULATOR_URL": prod_msg_url,
                "AUTH_SIGNING_SECRET": "sandbox_explicit_valid_secret_key_32bytes"
            })

    @pytest.mark.parametrize("adversarial_url", [
        "http://localhost@api.stripe.com/v1",
        "http://admin:password@localhost:8001",
        "http://user:pass@evil.com/sandbox-test",
        "http://93.184.216.34:8001",           # Public IP (example.com)
        "http://1.1.1.1:8001",                  # Public IP (Cloudflare)
        "http://8.8.8.8:8001",                  # Public IP (Google DNS)
        "http://[2001:db8::1]:8001",            # Non-loopback IPv6
        "http://evil-sandbox.attacker.com",     # Fake sandbox subdomain
        "http://sandbox.attacker.com",          # Fake sandbox domain
        "http://sandbox-bank.com.evil.org"      # Deceptive subdomain prefix
    ])
    def test_adversarial_url_tricks_and_public_ips_rejected(self, adversarial_url: str):
        """
        Requirement: Strict URL validation resilient to adversarial bypass tricks.
        Threat: Userinfo smuggling, public IP bypass, deceptive domain names.
        Control: Userinfo rejection, loopback IP verification, strict regex boundary anchor.
        """
        with pytest.raises(ProductionBoundaryViolationError):
            load_settings_from_env({
                "ENVIRONMENT": "sandbox",
                "SANDBOX_PAYMENT_SIMULATOR_URL": adversarial_url,
                "AUTH_SIGNING_SECRET": "sandbox_explicit_valid_secret_key_32bytes"
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
        Control: Regex pattern detection for live API key prefixes.
        """
        with pytest.raises(ProductionBoundaryViolationError, match="live production credential format|Detected live/production credential format"):
            load_settings_from_env({
                "ENVIRONMENT": "sandbox",
                "AUTH_SIGNING_SECRET": live_key
            })

    @pytest.mark.parametrize("unauthorized_env_var,var_value", [
        ("STRIPE_API_KEY", "sk_test_1234567890"),
        ("STRIPE_SECRET_KEY", "secret_value"),
        ("RAZORPAY_KEY_ID", "rzp_test_12345"),
        ("TWILIO_AUTH_TOKEN", "auth_token_value"),
        ("SENDGRID_API_KEY", "SG.1234567890"),
        ("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        ("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"),
        ("PROD_DATABASE_URL", "postgres://user:pass@prod-db.internal:5432/revenue"),
        ("PRODUCTION_HOST", "payments.prod.internal"),
        ("LIVE_GATEWAY_URL", "https://gateway.live.internal")
    ])
    def test_unauthorized_production_environment_variables_rejected(self, unauthorized_env_var: str, var_value: str):
        """
        Requirement: Fix environment loader bypass — prevent unauthorized production variables in process environment.
        Threat: Live infrastructure credentials/endpoints present in process environment but not declared in AppSettings.
        Control: `scan_environment_for_forbidden_production_artifacts()` scanning all environment keys & values.
        """
        with pytest.raises(ProductionBoundaryViolationError, match="Unauthorized production environment variable|live production credential format"):
            load_settings_from_env({
                "ENVIRONMENT": "sandbox",
                "AUTH_SIGNING_SECRET": "sandbox_explicit_valid_secret_key_32bytes",
                unauthorized_env_var: var_value
            })

    @pytest.mark.parametrize("weak_secret", [
        "",
        "   ",
        "short",
        "1234567890",
        "sandbox-default-signing-secret-do-not-use-in-prod",
        "default_secret",
        "password12345678"
    ])
    def test_weak_or_static_default_signing_secret_fails_closed(self, weak_secret: str):
        """
        Requirement: No static weak default signing secrets.
        Threat: Insecure static secret becoming authorization signing key.
        Control: Length, whitespace, and weak static dictionary checks.
        """
        with pytest.raises(ConfigurationError):
            AppSettings(
                environment="sandbox",
                auth_signing_secret=weak_secret,
                sandbox_payment_simulator_url="http://localhost:8001",
                sandbox_messaging_simulator_url="http://localhost:8002"
            )

    def test_ephemeral_sandbox_secret_generated_when_not_provided(self):
        """
        Requirement: Safe sandbox default generation without static hardcoded secret.
        Control: `generate_ephemeral_sandbox_signing_secret()` produces a high-entropy random key.
        """
        secret1 = generate_ephemeral_sandbox_signing_secret()
        secret2 = generate_ephemeral_sandbox_signing_secret()
        assert secret1 != secret2
        assert len(secret1) >= 32
        assert secret1.startswith("sandbox_session_secret_")

        config = load_settings_from_env({"ENVIRONMENT": "sandbox"})
        assert config.auth_signing_secret.startswith("sandbox_session_secret_")

    def test_require_explicit_secret_when_ephemeral_disallowed(self):
        """
        Requirement: Option to mandate explicit configuration of secrets.
        Control: `allow_ephemeral_secret=False` fails if secret not configured.
        """
        with pytest.raises(ConfigurationError, match="Missing required configuration: 'auth_signing_secret'"):
            load_settings_from_env({"ENVIRONMENT": "sandbox"}, allow_ephemeral_secret=False)

    def test_settings_immutability_prevents_runtime_tampering(self):
        """
        Requirement: Configuration validation cannot be bypassed at runtime by in-memory mutation.
        Threat: Application code modifying settings object after validation to point to production.
        Control: Frozen Pydantic model (`frozen=True`) preventing attribute reassignment.
        """
        config = load_settings_from_env({
            "ENVIRONMENT": "sandbox",
            "AUTH_SIGNING_SECRET": "sandbox_explicit_valid_secret_key_32bytes",
            "SANDBOX_PAYMENT_SIMULATOR_URL": "http://localhost:8001"
        })
        with pytest.raises(ValidationError):
            config.environment = "production"  # type: ignore

        with pytest.raises(ValidationError):
            config.sandbox_payment_simulator_url = "https://api.stripe.com"  # type: ignore

    def test_extra_unrecognized_fields_forbidden(self):
        """
        Requirement: Strict schema enforcement.
        Threat: Injecting unauthorized configuration keys through direct instantiation.
        Control: `extra="forbid"` on AppSettings.
        """
        with pytest.raises(ValidationError):
            AppSettings(
                environment="sandbox",
                auth_signing_secret="sandbox_explicit_valid_secret_key_32bytes",
                unauthorized_override="danger"
            )
