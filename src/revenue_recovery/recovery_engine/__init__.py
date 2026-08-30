"""Recovery Engine package for AI Revenue Recovery MVP.

Provides authoritative RecoveryCase lifecycle state machine, risk assessment, and diagnosis workflows.
"""

from src.revenue_recovery.recovery_engine.case_manager import (
    ALLOWED_TRANSITIONS,
    TERMINAL_STATES,
    CaseError,
    CaseFrozenError,
    CaseManager,
    CaseNotFoundError,
    InvalidStateTransitionError,
    MaxAttemptsExceededError,
)
from src.revenue_recovery.recovery_engine.diagnosis import (
    DiagnosisResult,
    RiskDiagnosisEvaluator,
    evaluate_diagnosis,
)

__all__ = [
    "ALLOWED_TRANSITIONS",
    "TERMINAL_STATES",
    "CaseError",
    "CaseFrozenError",
    "CaseManager",
    "CaseNotFoundError",
    "InvalidStateTransitionError",
    "MaxAttemptsExceededError",
    "DiagnosisResult",
    "RiskDiagnosisEvaluator",
    "evaluate_diagnosis",
]
