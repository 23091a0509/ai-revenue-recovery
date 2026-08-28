"""Foundation layer: Configuration, Security Safeguards, and Core Domain Contracts."""

from src.revenue_recovery.foundation.config import (
    AppSettings,
    ConfigurationError,
    ProductionBoundaryViolationError,
    generate_ephemeral_sandbox_signing_secret,
    get_settings,
    load_settings_from_env,
    reset_cached_settings,
    scan_environment_for_forbidden_production_artifacts,
)
from src.revenue_recovery.foundation.events import (
    ActionChannel,
    ActionType,
    CaseState,
    ComplianceObligation,
    DomainEventEnvelope,
    ExecutionStatus,
    FailureReason,
    ImmutableBaseModel,
    PaymentFailureEvent,
    RecoveryCase,
    RiskTier,
)

__all__ = [
    # Config & Safeguards
    "AppSettings",
    "ConfigurationError",
    "ProductionBoundaryViolationError",
    "generate_ephemeral_sandbox_signing_secret",
    "get_settings",
    "load_settings_from_env",
    "reset_cached_settings",
    "scan_environment_for_forbidden_production_artifacts",
    # Enums
    "CaseState",
    "RiskTier",
    "FailureReason",
    "ActionType",
    "ActionChannel",
    "ObligationType",
    "ExecutionStatus",
    # Domain Models & Events
    "ImmutableBaseModel",
    "PaymentFailureEvent",
    "RecoveryCase",
    "ComplianceObligation",
    "DomainEventEnvelope",
]
