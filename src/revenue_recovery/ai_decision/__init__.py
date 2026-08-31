"""AI Decision Engine package for AI Revenue Recovery MVP.

Provides recommendation-only AI decision artifacts and canonical input hashing (INV-01, INV-17).
"""

from src.revenue_recovery.ai_decision.artifacts import (
    DecisionArtifact,
    DecisionArtifactCreatedEvent,
    compute_canonical_input_hash,
    create_decision_artifact,
)
from src.revenue_recovery.ai_decision.engine import (
    AIDecisionEngine,
    AIModelProvider,
    DeterministicAIProvider,
)

__all__ = [
    "DecisionArtifact",
    "DecisionArtifactCreatedEvent",
    "compute_canonical_input_hash",
    "create_decision_artifact",
    "AIDecisionEngine",
    "AIModelProvider",
    "DeterministicAIProvider",
]
