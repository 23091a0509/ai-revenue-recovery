"""Unit and security tests for Sandbox Guard and URL Egress Firewall (TICKET-09).

Architecture Baseline: Frozen Architecture Baseline v11.
Proves technical egress boundary enforcement, production domain rejection,
IP literal blocking, deceptive userinfo rejection, DNS resolution, and anti-rebinding defense.
"""

from unittest.mock import MagicMock
import pytest

from src.revenue_recovery.executor import (
    EgressVerdict,
    SandboxGuard,
    SandboxViolationError,
    validate_egress_url,
)


class TestSandboxGuardProtocolAndSchemeEnforcement:
    """Tests for protocol schemes, format validation, and malformed inputs."""

    @pytest.fixture
    def guard(self) -> SandboxGuard:
        return SandboxGuard(dns_resolver=lambda host, port: ["127.0.0.1"])

    @pytest.mark.parametrize("loopback_url", [
        "http://localhost",
        "http://localhost:8001",
        "https://localhost:8443/payments/charge",
        "http://127.0.0.1:8001/v1/charge",
        "https://127.0.0.1:8002/v1/send",
        "http://[::1]:8001/status",
    ])
    def test_default_loopback_endpoints_pass(self, loopback_url: str):
        assert validate_egress_url(loopback_url) is True

    @pytest.mark.parametrize("valid_sandbox_url", [
        "http://localhost",
        "http://localhost:8001",
        "https://localhost:8443/payments/charge",
        "http://127.0.0.1:8001/v1/charge",
        "https://127.0.0.1:8002/v1/send",
        "http://[::1]:8001/status",
        "http://sandbox-simulator:8001",
        "http://payments.sandbox:8001",
    ])
    def test_allowed_sandbox_endpoints_pass(self, guard: SandboxGuard, valid_sandbox_url: str):
        assert guard.check_egress_allowed(valid_sandbox_url) is True
        assert guard.is_url_allowed(valid_sandbox_url) is True

    @pytest.mark.parametrize("bad_scheme_url", [
        "ftp://localhost:8001/file",
        "file:///etc/passwd",
        "file://C:/Windows/System32",
        "gopher://localhost:70",
        "ws://localhost:8001",
        "wss://localhost:8001",
        "javascript:alert(1)",
        "data:text/html,<h1>test</h1>",
        "ssh://git@github.com",
    ])
    def test_forbidden_schemes_strictly_rejected(self, guard: SandboxGuard, bad_scheme_url: str):
        with pytest.raises(SandboxViolationError, match="Forbidden protocol scheme"):
            guard.check_egress_allowed(bad_scheme_url)
        assert guard.is_url_allowed(bad_scheme_url) is False

    @pytest.mark.parametrize("empty_or_malformed", [
        "",
        "   ",
        None,
        "not_a_url",
        "http://",
        "http://   localhost:8001",
        "http://localhost:8001/path with spaces",
    ])
    def test_empty_or_malformed_urls_rejected(self, guard: SandboxGuard, empty_or_malformed):
        with pytest.raises(SandboxViolationError):
            guard.check_egress_allowed(empty_or_malformed)
        assert guard.is_url_allowed(empty_or_malformed) is False


class TestSandboxGuardProductionDomainBlocking:
    """Tests blocking all production payment and messaging domains across casing and variations."""

    @pytest.fixture
    def guard(self) -> SandboxGuard:
        return SandboxGuard()

    @pytest.mark.parametrize("prod_url", [
        "https://api.stripe.com/v1/charges",
        "https://API.STRIPE.COM/v1/charges",
        "http://api.stripe.com:80/v1/charges",
        "https://api.stripe.com:443/v1/charges",
        "https://api.stripe.com./v1/charges",
        "https://api.razorpay.com/v1/payments",
        "https://API.RAZORPAY.COM/v1/payments",
        "https://api.paypal.com/v2/checkout/orders",
        "https://api.braintreegateway.com/merchants",
        "https://api.adyen.com/v68/payments",
        "https://api.squareup.com/v2/payments",
        "https://api.checkout.com/payments",
        "https://api.twilio.com/2010-04-01/Accounts",
        "https://API.TWILIO.COM/2010-04-01/Accounts",
        "https://api.sendgrid.com/v3/mail/send",
        "https://api.mailgun.net/v3",
        "https://graph.facebook.com/v17.0/messages",
        "https://api.whatsapp.com/v1/messages",
        "https://api.plaid.com/v1",
        "https://subdomain.api.stripe.com/charges",
    ])
    def test_production_domains_strictly_blocked(self, guard: SandboxGuard, prod_url: str):
        with pytest.raises(SandboxViolationError, match="Production egress blocked"):
            guard.check_egress_allowed(prod_url)
        assert guard.is_url_allowed(prod_url) is False


class TestSandboxGuardAdversarialAndDeceptiveAttacks:
    """Tests security boundaries against userinfo bypasses, deceptive subdomains, and public IPs."""

    @pytest.fixture
    def guard(self) -> SandboxGuard:
        return SandboxGuard()

    @pytest.mark.parametrize("userinfo_url", [
        "http://user:password@localhost:8001",
        "http://localhost@api.stripe.com/v1",
        "https://admin:secret@127.0.0.1:8001",
        "http://foo:bar@sandbox-simulator:8001",
    ])
    def test_userinfo_and_credentials_rejected(self, guard: SandboxGuard, userinfo_url: str):
        with pytest.raises(SandboxViolationError, match="embedded userinfo/credentials"):
            guard.check_egress_allowed(userinfo_url)
        assert guard.is_url_allowed(userinfo_url) is False

    @pytest.mark.parametrize("deceptive_host_url", [
        "http://evil-sandbox.attacker.com",
        "http://sandbox.attacker.com",
        "http://sandbox-bank.com.evil.org",
        "http://evil.com/sandbox-simulator",
        "http://api.stripe.com.attacker.com/v1",
        "http://localhost.evil.com",
    ])
    def test_deceptive_subdomains_and_external_hosts_rejected(self, guard: SandboxGuard, deceptive_host_url: str):
        with pytest.raises(SandboxViolationError, match="is not an authorized sandbox endpoint"):
            guard.check_egress_allowed(deceptive_host_url)
        assert guard.is_url_allowed(deceptive_host_url) is False

    @pytest.mark.parametrize("public_ip_url", [
        "http://93.184.216.34:8001",
        "http://1.1.1.1:8001",
        "http://8.8.8.8:8001",
        "http://[2001:db8::1]:8001",
        "http://10.0.0.1:8001",
        "http://192.168.1.1:8001",
    ])
    def test_public_and_non_loopback_ips_blocked(self, guard: SandboxGuard, public_ip_url: str):
        with pytest.raises(SandboxViolationError, match="Public or non-loopback IP address"):
            guard.check_egress_allowed(public_ip_url)
        assert guard.is_url_allowed(public_ip_url) is False


class TestDnsResolutionAndAntiRebinding:
    """Deterministic security tests for DNS resolution verification and rebinding protection."""

    def test_allowed_hostname_resolving_to_loopback_is_permitted(self):
        mock_resolver = MagicMock(return_value=["127.0.0.1"])
        guard = SandboxGuard(dns_resolver=mock_resolver)
        assert guard.check_egress_allowed("http://sandbox-simulator:8001/status") is True
        mock_resolver.assert_called_once_with("sandbox-simulator", 8001)

    def test_allowed_hostname_resolving_to_public_ip_fails_closed(self):
        # Adversary controls DNS for allowed name and returns public IP (DNS Rebinding)
        mock_resolver = MagicMock(return_value=["93.184.216.34"])
        guard = SandboxGuard(dns_resolver=mock_resolver)
        with pytest.raises(SandboxViolationError, match="DNS rebinding / security violation"):
            guard.check_egress_allowed("http://sandbox-simulator:8001/charge")

    def test_allowed_hostname_resolving_to_rfc1918_private_ip_fails_closed(self):
        mock_resolver = MagicMock(return_value=["192.168.1.50"])
        guard = SandboxGuard(dns_resolver=mock_resolver)
        with pytest.raises(SandboxViolationError, match="DNS rebinding / security violation"):
            guard.check_egress_allowed("http://payments.sandbox:8001/charge")

    def test_allowed_hostname_with_multi_record_dns_fails_if_any_ip_is_non_loopback(self):
        # Multiple A records: one loopback, one malicious public IP
        mock_resolver = MagicMock(return_value=["127.0.0.1", "203.0.113.195"])
        guard = SandboxGuard(dns_resolver=mock_resolver)
        with pytest.raises(SandboxViolationError, match="DNS rebinding / security violation"):
            guard.check_egress_allowed("http://sandbox-simulator:8001/charge")

    def test_dns_resolution_failure_fails_closed(self):
        def failing_resolver(host: str, port: int):
            raise RuntimeError("DNS Name Not Found (NXDOMAIN)")

        guard = SandboxGuard(dns_resolver=failing_resolver)
        with pytest.raises(SandboxViolationError, match="DNS resolution failed"):
            guard.check_egress_allowed("http://sandbox-simulator:8001/charge")

    def test_dns_resolution_empty_records_fails_closed(self):
        mock_resolver = MagicMock(return_value=[])
        guard = SandboxGuard(dns_resolver=mock_resolver)
        with pytest.raises(SandboxViolationError, match="DNS resolution returned zero records"):
            guard.check_egress_allowed("http://sandbox-simulator:8001/charge")


class TestSandboxGuardCustomConfiguration:
    """Tests custom allowed hosts and forbidden domain additions."""

    def test_custom_allowed_hosts(self):
        custom_guard = SandboxGuard(
            custom_allowed_hosts=["internal-mock-gateway.local"],
            dns_resolver=lambda host, port: ["127.0.0.1"]
        )
        assert custom_guard.check_egress_allowed("http://internal-mock-gateway.local:9000/charge") is True
        assert custom_guard.check_egress_allowed("http://localhost:8001") is True

    def test_custom_forbidden_domains(self):
        custom_guard = SandboxGuard(custom_forbidden_domains=["api.unauthorized-vendor.com"])
        with pytest.raises(SandboxViolationError, match="Production egress blocked"):
            custom_guard.check_egress_allowed("https://api.unauthorized-vendor.com/v1/data")

    def test_custom_port_restriction(self):
        restricted_guard = SandboxGuard(allow_custom_ports=False)
        # Port 8001 is in ALLOWED_SANDBOX_PORTS
        assert restricted_guard.check_egress_allowed("http://localhost:8001") is True
        # Port 9999 is NOT in ALLOWED_SANDBOX_PORTS
        with pytest.raises(SandboxViolationError, match="is not in the allowed sandbox simulator ports list"):
            restricted_guard.check_egress_allowed("http://localhost:9999")
