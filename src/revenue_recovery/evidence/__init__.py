"""Evidence & Experiment Engine Public Module.

Authoritative Baseline: Frozen Architecture Baseline v11.
"""

from src.revenue_recovery.evidence.evidence_engine import (
    BlockingReason,
    EvidenceCalculatedEvent,
    EvidenceEngine,
    EvidenceMetricEntry,
    ReportingState,
)
from src.revenue_recovery.evidence.experiment import (
    ExperimentAssignmentRecord,
    ExperimentAssignedEvent,
    ExperimentConfig,
    ExperimentEngine,
    StratumKey,
)
from src.revenue_recovery.governance.arbitrator import ExperimentAssignment

__all__ = [
    "ExperimentAssignment",
    "StratumKey",
    "ExperimentConfig",
    "ExperimentAssignmentRecord",
    "ExperimentAssignedEvent",
    "ExperimentEngine",
    "ReportingState",
    "BlockingReason",
    "EvidenceMetricEntry",
    "EvidenceCalculatedEvent",
    "EvidenceEngine",
]
