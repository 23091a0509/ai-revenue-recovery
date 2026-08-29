"""Conformance test suite for INV-05: Strict MVP Sandbox Isolation.

Architecture Baseline: Frozen Architecture Baseline v11.
Verifies that the SandboxGuard egress firewall technical controls meet the requirements of INV-05,
ensuring all non-sandbox outbound destinations fail closed.

NOTE on Conformance Status:
While this test verifies the technical URL egress firewall controls (TICKET-09),
INV-05 remains NOT PROVEN until full end-to-end runtime Executor integration (TICKET-10)
and simulator verification (TICKET-11/12) are completed.
"""

import pytest

from src.revenue_recovery.executor import (
    SandboxGuard,
    SandboxViolationError,
    validate_egress_url,
)
from src.revenue_recovery.foundation.config import (
    FORBIDDEN_PRODUCTION_DOMAINS,
    AppSettings,
)


class TestSandboxIsolationConformance:
    """Conformance checks for strict MVP sandbox network boundary enforcement."""

    def test_sandbox_guard_rejects_all_forbidden_production_domains(self):
        guard = SandboxGuard()
        for domain in FORBIDDEN_PRODUCTION_DOMAINS:
            url_http = f"http://{domain}/v1/resource"
            url_https = f"https://{domain}/v1/resource"
            with pytest.raises(SandboxViolationError):
                guard.check_egress_allowed(url_http)
            with pytest.raises(SandboxViolationError):
                guard.check_egress_allowed(url_https)

    def test_default_config_settings_endpoints_pass_sandbox_guard(self):
        settings = AppSettings(
            auth_signing_secret="explicit-secure-sandbox-signing-secret-12345"
        )
        guard = SandboxGuard()
        assert guard.check_egress_allowed(settings.sandbox_payment_simulator_url) is True
        assert guard.check_egress_allowed(settings.sandbox_messaging_simulator_url) is True

    def test_arbitrary_internet_domains_fail_closed(self):
        guard = SandboxGuard()
        external_domains = [
            "https://google.com",
            "https://example.org",
            "https://mycompany.com",
            "http://142.250.190.46",
        ]
        for url in external_domains:
            with pytest.raises(SandboxViolationError):
                guard.check_egress_allowed(url)
            assert guard.is_url_allowed(url) is False

    def test_convenience_function_matches_guard_instance(self):
        assert validate_egress_url("http://localhost:8001") is True
        with pytest.raises(SandboxViolationError):
            validate_egress_url("https://api.stripe.com")
