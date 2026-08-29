"""Sandbox Guard and URL Egress Firewall for AI Revenue Recovery MVP.

Architecture Baseline: Frozen Architecture Baseline v11.
Enforces technical network isolation (INV-05) preventing outbound execution
calls from reaching live payment processors, communication gateways, public IPs,
or deceptive/unauthorized destinations, including DNS rebinding defense.
"""

from enum import Enum
import ipaddress
import re
import socket
from typing import Callable, Sequence, Set
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


def _default_dns_resolver(host: str, port: int = 80) -> list[str]:
    """Default system DNS resolver using socket.getaddrinfo."""
    try:
        addr_info = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        resolved_ips: list[str] = []
        for item in addr_info:
            sockaddr = item[4]
            ip_str = sockaddr[0]
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)
        return resolved_ips
    except Exception as exc:
        raise SandboxViolationError(f"DNS resolution failure for host '{host}': {exc}") from exc


class SandboxGuard:
    """
    Fail-closed URL egress firewall ensuring outbound HTTP requests
    target ONLY authorized local or sandbox simulator endpoints.
    Protects against DNS rebinding by resolving hostnames and validating all A/AAAA IP targets.
    """

    def __init__(
        self,
        custom_allowed_hosts: Sequence[str] | None = None,
        custom_forbidden_domains: Sequence[str] | None = None,
        allow_custom_ports: bool = True,
        resolve_dns: bool = True,
        dns_resolver: Callable[[str, int], Sequence[str]] | None = None
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
        self._resolve_dns = resolve_dns
        self._dns_resolver = dns_resolver or _default_dns_resolver

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

        # 6. Port Validation
        port = parsed.port or (443 if scheme == "https" else 80)
        if parsed.port is not None:
            if not self._allow_custom_ports and parsed.port not in ALLOWED_SANDBOX_PORTS:
                raise SandboxViolationError(
                    f"Port '{parsed.port}' is not in the allowed sandbox simulator ports list: {ALLOWED_SANDBOX_PORTS}"
                )

        # 7. Hostname Syntax Allowlist Evaluation
        is_allowed_name = False
        if normalized_host in self._allowed_hosts:
            is_allowed_name = True
        else:
            for pattern in ALLOWED_SANDBOX_HOST_PATTERNS:
                if pattern.match(normalized_host):
                    is_allowed_name = True
                    break

        # 8. IP Literal or DNS Resolution Evaluation (Anti-Rebinding Defense)
        is_ip_literal = False
        ip_obj = None
        try:
            ip_obj = ipaddress.ip_address(normalized_host)
            is_ip_literal = True
        except ValueError:
            pass

        if is_ip_literal and ip_obj is not None:
            if not ip_obj.is_loopback:
                raise SandboxViolationError(
                    f"Public or non-loopback IP address '{normalized_host}' is blocked in sandbox mode."
                )
            return True

        if not is_allowed_name:
            raise SandboxViolationError(
                f"Egress violation: Destination host '{normalized_host}' is not an authorized sandbox endpoint."
            )

        # 9. DNS Resolution & IP Boundary Check (Resolves hostname to ensure all targets are loopback)
        if self._resolve_dns:
            resolved_ips = self._resolve_host(normalized_host, port)
            if not resolved_ips:
                raise SandboxViolationError(
                    f"DNS resolution returned zero records for allowed host '{normalized_host}'. Failing closed."
                )

            for ip_str in resolved_ips:
                try:
                    res_ip = ipaddress.ip_address(ip_str)
                except ValueError as err:
                    raise SandboxViolationError(
                        f"DNS resolution returned malformed IP '{ip_str}' for host '{normalized_host}': {err}"
                    ) from err

                if not res_ip.is_loopback:
                    raise SandboxViolationError(
                        f"DNS rebinding / security violation: Host '{normalized_host}' resolved to non-loopback IP '{ip_str}'. Blocked by egress firewall."
                    )

        return True

    def _resolve_host(self, host: str, port: int) -> Sequence[str]:
        """Resolves host using configured resolver, with deterministic fallback for localhost/127.0.0.1/::1."""
        if host in ("localhost", "127.0.0.1"):
            return ["127.0.0.1"]
        if host == "::1":
            return ["::1"]
        try:
            return self._dns_resolver(host, port)
        except SandboxViolationError:
            raise
        except Exception as exc:
            raise SandboxViolationError(
                f"DNS resolution failed for host '{host}': {exc}"
            ) from exc

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
