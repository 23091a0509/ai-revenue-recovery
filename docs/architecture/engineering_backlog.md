# Engineering Backlog & Implementation Sequence

This backlog breaks down the **AI Revenue Recovery MVP** into atomic, verifiable milestones ordered strictly by architectural dependency.

---

## Dependency Graph & Implementation Sequence

```
MILESTONE 1: Foundation & Data Contracts
      │ (Core models, Event contracts, Sandbox Configuration Guard, Audit Logger)
      ▼
MILESTONE 2: Execution Safety & Cryptographic Authorizer
      │ (ActionAuthorization token minter, Verifier, Kill Switch, Sandbox Guard)
      ▼
MILESTONE 3: Action Executor & Sandbox Simulators
      │ (Idempotent mock payment/messaging simulator execution, Non-sandbox rejection)
      ▼
MILESTONE 4: Case Management, Risk & Diagnosis Engine
      │ (Ingestion, Risk scoring, Diagnosis state machine)
      ▼
MILESTONE 5: AI Decision Engine & Decision Artifacts
      │ (Immutable Decision Artifacts, Canonical hash snapshot, Recommendation only)
      ▼
MILESTONE 6: Governance Engine (Policy, Scheduler, Arbitrator)
      │ (Deterministic policy engine, Compliance scheduler collision handler, Arbitrator)
      ▼
MILESTONE 7: Financial Reconciliation & Revenue Ledger
      │ (Two-stage ledger: gross vs confirmed settled, dispute & partial payment handling)
      ▼
MILESTONE 8: Experimentation & Evidence Engine
      │ (Stratification, Lift calculation, Evidence states & blocking reasons)
      ▼
MILESTONE 9: End-to-End Sandbox Recovery Integration & Full Conformance Suite
```

---

## Detailed Engineering Tickets

### Milestone 1: Foundation & Data Contracts
- **TICKET-01**: Implement environment configuration & production safeguard validator (`src/revenue_recovery/foundation/config.py`). Ensures no production credentials or network paths can exist in sandbox.
- **TICKET-02**: Implement core domain models & event contracts (`src/revenue_recovery/foundation/events.py`).
- **TICKET-03**: Implement append-only cryptographic audit logger (`src/revenue_recovery/foundation/audit.py`).
- **TICKET-04**: Write tests for Config, Events, and Audit contracts (`tests/unit/test_foundation.py`).

### Milestone 2: Execution Safety & Cryptographic Authorizer
- **TICKET-05**: Implement `ActionAuthorization` model, ECDSA/HMAC signing and token verification (`src/revenue_recovery/safety/authorizer.py`).
- **TICKET-06**: Implement fail-closed global and granular Kill Switch (`src/revenue_recovery/safety/kill_switch.py`).
- **TICKET-07**: Implement Circuit Breaker & capacity governor (`src/revenue_recovery/safety/circuit_breaker.py`).
- **TICKET-08**: Write unit and security tests for Authorizer, Kill Switch, and Token Tampering (`tests/unit/test_safety.py`).

### Milestone 3: Sandbox Action Executor
- **TICKET-09**: Implement Sandbox Guard with URL egress firewall (`src/revenue_recovery/executor/sandbox_guard.py`).
- **TICKET-10**: Implement Idempotent Action Executor requiring verified tokens (`src/revenue_recovery/executor/executor.py`).
- **TICKET-11**: Implement Mock Payment & Messaging Simulators (`src/revenue_recovery/executor/simulators.py`).
- **TICKET-12**: Write execution & security tests (`tests/unit/test_executor.py`).

### Milestone 4: Recovery Engine
- **TICKET-13**: Implement Recovery Case domain model & lifecycle state machine (`src/revenue_recovery/recovery_engine/case_manager.py`).
- **TICKET-14**: Implement deterministic Risk & Diagnosis evaluator (`src/revenue_recovery/recovery_engine/diagnosis.py`).
- **TICKET-15**: Write Case Management & Diagnosis tests (`tests/unit/test_recovery_engine.py`).

### Milestone 5: AI Decision Engine & Decision Artifacts
- **TICKET-16**: Implement immutable `DecisionArtifact` model with SHA-256 canonical input hashing (`src/revenue_recovery/ai_decision/artifacts.py`).
- **TICKET-17**: Implement recommendation-only AI engine connector (`src/revenue_recovery/ai_decision/engine.py`).
- **TICKET-18**: Write tests verifying AI outputs only recommendation artifacts and cannot execute (`tests/unit/test_ai_decision.py`).

### Milestone 6: Governance Engine
- **TICKET-19**: Implement Policy Engine with rule hierarchy and conflict resolution (`src/revenue_recovery/governance/policy_engine.py`).
- **TICKET-20**: Implement deterministic Compliance Scheduler with multi-way collision resolver (`src/revenue_recovery/governance/scheduler.py`).
- **TICKET-21**: Implement Control-Plane Arbitrator coordinating Safety, Compliance, Experiment, and Capacity (`src/revenue_recovery/governance/arbitrator.py`).
- **TICKET-22**: Write property-based and collision tests (`tests/unit/test_governance.py`).

### Milestone 7: Financial Reconciliation & Revenue Ledger
- **TICKET-23**: Implement append-only two-stage Revenue Ledger (`src/revenue_recovery/reconciliation/ledger.py`).
- **TICKET-24**: Implement Settlement & Dispute reconciliation engine (`src/revenue_recovery/reconciliation/dispute_handler.py`).
- **TICKET-25**: Write tests proving gross recovery is not treated as confirmed recovery until settlement (`tests/unit/test_reconciliation.py`).

### Milestone 8: Evidence & Experiment Engine
- **TICKET-26**: Implement randomized controlled experiment stratification & assignment (`src/revenue_recovery/evidence/experiment.py`).
- **TICKET-27**: Implement Evidence Registry with required metric reporting states & blocking reason codes (`src/revenue_recovery/evidence/evidence_engine.py`).
- **TICKET-28**: Write tests verifying metrics cannot silently disappear and lift claims require valid experiment data (`tests/unit/test_evidence.py`).

### Milestone 9: Full Conformance Suite
- **TICKET-29**: Implement End-to-End Sandbox Recovery workflow test suite (`tests/integration/test_end_to_end_recovery.py`).
- **TICKET-30**: Implement automated Architecture Conformance test suite verifying all 18 invariants (`tests/conformance/test_architecture_conformance.py`).
