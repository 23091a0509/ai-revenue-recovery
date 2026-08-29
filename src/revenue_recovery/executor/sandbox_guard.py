"""Sandbox Guard and URL Egress Firewall for AI Revenue Recovery MVP.

Architecture Baseline: Frozen Architecture Baseline v11.
Enforces technical network isolation (INV-05) preventing outbound execution
calls from reaching live payment processors, communication gateways, public IPs,
or deceptive/unauthorized destinations.
"""

from enum import Enum
import ipaddress
import re
from typing import Sequence, Set
from urllib.parse import urlparse

from src.revenue_recovery.foundation.config import (
    FORBIDDEN_PRODUCTION_DOMAINS,
    ProductionBoundaryViolationError,
)


class SandboxViolationError(ProductionBoundaryViolationError):
    """Raised when an outbound network destination violates MVP sandbox egress isolation policies."""
    pass


class EgressVerdict(str, Enum):
    """Egress evaluation verdict."""
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"


# Allowed host patterns for sandbox execution
ALLOWED_SANDBOX_HOST_PATTERNS = [
    re.compile(r"^localhost$", re.IGNORECASE),
    re.compile(r"^127\.0\.0\.1$"),
    re.compile(r"^::1$"),
    re.compile(r"^sandbox-[a-zA-Z0-9\-]+$", re.IGNORECASE),
    re.compile(r"^[a-zA-Z0-9\-]+\.sandbox$", re.IGNORECASE),
]

# Standard allowed sandbox simulator ports
ALLOWED_SANDBOX_PORTS = {80, 443, 8000, 8001, 8002, 8003, 8080, 8443, 3000, 5000}


class SandboxGuard:
    """
    Fail-closed URL egress firewall ensuring outbound HTTP requests
    target ONLY authorized local or sandbox simulator endpoints.
    """

    def __init__(
        self,
        custom_allowed_hosts: Sequence[str] | None = None,
        custom_forbidden_domains: Sequence[str] | None = None,
        allow_custom_ports: bool = True
    ) -> None:
        self._allowed_hosts: Set[str] = {
            "localhost",
            "127.0.0.1",
            "::1",
            *(h.lower() for h in (custom_allowed_hosts or []))
        }
        self._forbidden_domains: Set[str] = {
            *(d.lower() for d in FORBIDDEN_PRODUCTION_DOMAINS),
            *(d.lower() for d in (custom_forbidden_domains or []))
        }
        self._allow_custom_ports = allow_custom_ports

    def check_egress_allowed(self, url: str) -> bool:
        """
        Validates whether outbound communication to the target URL is permitted.
        Raises SandboxViolationError if the URL violates sandbox egress rules.
        Returns True if permitted.
        """
        if not url or not isinstance(url, str) or not url.strip():
            raise SandboxViolationError("Egress URL cannot be empty or non-string")

        cleaned_url = url.strip()

        # 1. Reject embedded whitespace or control characters
        if any(c.isspace() for c in cleaned_url):
            raise SandboxViolationError(f"Malicious URL containing whitespace detected: '{cleaned_url}'")

        try:
            parsed = urlparse(cleaned_url)
        except Exception as exc:
            raise SandboxViolationError(f"Malformed URL cannot be parsed: '{cleaned_url}'") from exc

        # 2. Protocol / Scheme Enforcement (Only http and https)
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            raise SandboxViolationError(
                f"Forbidden protocol scheme '{scheme}' in '{cleaned_url}'. Only 'http' and 'https' are allowed in sandbox."
            )

        # 3. Userinfo / Embedded Credentials Defense (e.g. http://user:pass@host or http://localhost@evil.com)
        if parsed.username or parsed.password or "@" in (parsed.netloc.split(":")[0] if parsed.netloc else ""):
            raise SandboxViolationError(
                f"Egress URL contains embedded userinfo/credentials which is forbidden: '{cleaned_url}'"
            )

        # 4. Hostname Extraction and Normalization
        hostname = parsed.hostname
        if not hostname:
            raise SandboxViolationError(f"Egress URL missing valid hostname: '{cleaned_url}'")

        normalized_host = hostname.strip().lower().rstrip(".")

        # 5. Production Domain Blacklist Check (Case-insensitive, trailing dots stripped)
        for forbidden in self._forbidden_domains:
            if normalized_host == forbidden or normalized_host.endswith("." + forbidden):
                raise SandboxViolationError(
                    f"Production egress blocked: Target domain '{normalized_host}' is a forbidden production endpoint."
                )

        # 6. Public IP Address & Non-Loopback IP Blocking
        is_ip_literal = False
        ip_obj = None
        try:
            ip_obj = ipaddress.ip_address(normalized_host)
            is_ip_literal = True
        except ValueError:
            # Not an IP literal, proceed to hostname evaluation
            pass

        if is_ip_literal and ip_obj is not None:
            if not ip_obj.is_loopback:
                raise SandboxViolationError(
                    f"Public or non-loopback IP address '{normalized_host}' is blocked in sandbox mode."
                )
            # Valid loopback IP (127.0.0.1 or ::1) is permitted
            return True

        # 7. Port Validation
        if parsed.port is not None:
            if not self._allow_custom_ports and parsed.port not in ALLOWED_SANDBOX_PORTS:
                raise SandboxViolationError(
                    f"Port '{parsed.port}' is not in the allowed sandbox simulator ports list: {ALLOWED_SANDBOX_PORTS}"
                )

        # 8. Host Allowlist Matching
        if normalized_host in self._allowed_hosts:
            return True

        # 9. Sandbox Pattern Matching (e.g. sandbox-simulator, myapp.sandbox)
        for pattern in ALLOWED_SANDBOX_HOST_PATTERNS:
            if pattern.match(normalized_host):
                return True

        # Default Fail-Closed
        raise SandboxViolationError(
            f"Egress violation: Destination host '{normalized_host}' is not an authorized sandbox endpoint."
        )

    def is_url_allowed(self, url: str) -> bool:
        """Non-raising query method returning True if allowable, False otherwise."""
        try:
            return self.check_egress_allowed(url)
        except SandboxViolationError:
            return False


# Global default validator instance
_DEFAULT_GUARD = SandboxGuard()


def validate_egress_url(url: str) -> bool:
    """Convenience function validating an egress URL against default sandbox firewall policies."""
    return _DEFAULT_GUARD.check_egress_allowed(url)
