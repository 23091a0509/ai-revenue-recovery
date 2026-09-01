"""Recommendation-only AI Decision Engine connector (TICKET-17).

Architecture Baseline: Frozen Architecture Baseline v11.
Enforces:
- INV-01: AI recommends; it does not execute (Zero execution / authorization authority).
- INV-02: Least-privilege authority boundaries (Isolated recommendation service).
- INV-17: Immutable Decision Artifacts with SHA-256 canonical input snapshot hashing.
- INV-18: Complete audit logging of decision artifact creations via append-only logger.
"""

from datetime import datetime, timezone
from typing import Optional, Protocol, runtime_checkable

from src.revenue_recovery.ai_decision.artifacts import (
    DecisionArtifact,
    DecisionArtifactCreatedEvent,
    compute_canonical_input_hash,
    create_decision_artifact,
)
from src.revenue_recovery.foundation.audit import CryptographicAuditLogger
from src.revenue_recovery.foundation.events import (
    CaseState,
    RecoveryCase,
)
from src.revenue_recovery.recovery_engine.diagnosis import DiagnosisResult


@runtime_checkable
class AIModelProvider(Protocol):
    """Protocol defining the interface for recommendation-only AI model connectors."""

    def generate_recommendation(
        self,
        case: RecoveryCase,
        diagnosis: DiagnosisResult,
        current_time: Optional[datetime] = None,
    ) -> DecisionArtifact:
        """Generates an immutable DecisionArtifact recommendation for a diagnosed case."""
        ...


class DeterministicAIProvider:
    """
    Default deterministic rule-based AI recommendation provider for MVP and offline evaluation.
    Provides mathematically reproducible recommendations with zero external network dependencies.
    """

    def __init__(
        self,
        model_version: str = "mock-decision-v1.0.0",
        prompt_version: str = "v1.0.0",
        tool_schema_version: str = "v1.0.0",
    ) -> None:
        self.model_version = model_version
        self.prompt_version = prompt_version
        self.tool_schema_version = tool_schema_version

    def generate_recommendation(
        self,
        case: RecoveryCase,
        diagnosis: DiagnosisResult,
        current_time: Optional[datetime] = None,
    ) -> DecisionArtifact:
        """Generates a deterministic DecisionArtifact using canonical input hashing."""
        return create_decision_artifact(
            case=case,
            diagnosis=diagnosis,
            model_version=self.model_version,
            prompt_version=self.prompt_version,
            tool_schema_version=self.tool_schema_version,
        )


class AIDecisionEngine:
    """
    Recommendation-only AI Decision Engine.
    
    Architectural Boundaries (v11 Baseline):
    - Read Access: Case context, Diagnosis snapshot.
    - Decision Role: Recommendations only (emits immutable DecisionArtifact).
    - Authorize Role: None (Zero token minting capabilities).
    - Execute Role: None (Zero execution or provider calling capabilities).
    - Network Egress: None in MVP / Isolated LLM provider only.
    """

    def __init__(
        self,
        provider: Optional[AIModelProvider] = None,
        audit_logger: Optional[CryptographicAuditLogger] = None,
    ) -> None:
        self.provider: AIModelProvider = provider or DeterministicAIProvider()
        self.audit_logger: Optional[CryptographicAuditLogger] = audit_logger

    def evaluate_case(
        self,
        case: RecoveryCase,
        diagnosis: DiagnosisResult,
        current_time: Optional[datetime] = None,
    ) -> DecisionArtifact:
        """
        Evaluates a diagnosed recovery case and returns an advisory DecisionArtifact.
        
        Guards:
        - Case must be in DIAGNOSED or EVALUATING state.
        - Verifies integrity of canonical input hash on the generated artifact.
        - Appends an immutable DECISION_ARTIFACT_CREATED event to audit logger if present.
        """
        now = current_time or datetime.now(timezone.utc)

        # Enforce state precondition: Case must be diagnosed
        if case.state not in {CaseState.DIAGNOSED, CaseState.EVALUATING}:
            raise ValueError(
                f"AIDecisionEngine cannot evaluate case '{case.case_id}' in state '{case.state}'. "
                f"Case must be in DIAGNOSED or EVALUATING state."
            )

        # Generate recommendation via model provider
        artifact = self.provider.generate_recommendation(
            case=case,
            diagnosis=diagnosis,
            current_time=now,
        )

        # Verify hash integrity (INV-17)
        expected_hash = compute_canonical_input_hash(artifact.input_snapshot)
        if artifact.canonical_input_hash != expected_hash:
            raise ValueError(
                f"Corrupted DecisionArtifact input hash: got '{artifact.canonical_input_hash}', "
                f"expected '{expected_hash}'"
            )

        # Record audit log entry if logger is configured (INV-18)
        if self.audit_logger is not None:
            created_event = DecisionArtifactCreatedEvent(
                artifact_id=artifact.artifact_id,
                case_id=artifact.case_id,
                canonical_input_hash=artifact.canonical_input_hash,
                model_version=artifact.model_version,
                recommended_action=artifact.recommended_action,
                occurred_at=now,
            )
            self.audit_logger.append(
                event_type="DECISION_ARTIFACT_CREATED",
                payload=created_event.model_dump(mode="json"),
                timestamp=now,
            )

        return artifact
