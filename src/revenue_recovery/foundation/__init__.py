"""Foundation layer: Configuration, Security Safeguards, and Core Domain Contracts."""

from src.revenue_recovery.foundation.audit import (
    GENESIS_PREVIOUS_HASH,
    AuditEntry,
    AuditIntegrityError,
    CryptographicAuditLogger,
    ImmutableDict,
    canonical_json,
    compute_entry_hash,
    freeze_payload,
)
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
    CaseDiagnosedEvent,
    CaseState,
    ComplianceObligation,
    DomainEventEnvelope,
    ExecutionStatus,
    FailureReason,
    ImmutableBaseModel,
    ObligationType,
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
    "CaseDiagnosedEvent",
    "DomainEventEnvelope",
    # Cryptographic Audit
    "GENESIS_PREVIOUS_HASH",
    "AuditEntry",
    "AuditIntegrityError",
    "CryptographicAuditLogger",
    "ImmutableDict",
    "canonical_json",
    "compute_entry_hash",
    "freeze_payload",
]
