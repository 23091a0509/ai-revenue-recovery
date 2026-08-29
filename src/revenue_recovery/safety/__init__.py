"""Safety layer: Execution safety, cryptographic authorization, kill switch, and circuit breakers."""

from src.revenue_recovery.safety.authorizer import (
    ActionAuthorization,
    AuthorizationStatus,
    AuthorizationVerificationError,
    CryptographicAuthorizer,
    canonical_signing_string,
    validate_authorizer_signing_secret,
)
from src.revenue_recovery.safety.circuit_breaker import (
    CapacityExceededError,
    CapacityGovernor,
    CircuitBreaker,
    CircuitBreakerState,
    CircuitBrokenError,
    GranularCircuitBreakerRegistry,
    SafetyVerdict,
)
from src.revenue_recovery.safety.kill_switch import (
    KillSwitchActiveError,
    KillSwitchManager,
    KillSwitchRecord,
    KillSwitchScope,
)

__all__ = [
    "ActionAuthorization",
    "AuthorizationStatus",
    "AuthorizationVerificationError",
    "CryptographicAuthorizer",
    "canonical_signing_string",
    "validate_authorizer_signing_secret",
    "KillSwitchActiveError",
    "KillSwitchManager",
    "KillSwitchRecord",
    "KillSwitchScope",
    "CircuitBreakerState",
    "SafetyVerdict",
    "CircuitBrokenError",
    "CapacityExceededError",
    "CircuitBreaker",
    "GranularCircuitBreakerRegistry",
    "CapacityGovernor",
]
