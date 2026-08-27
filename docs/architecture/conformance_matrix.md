# Architecture Conformance Matrix
**Baseline:** Implementation Plan v11 (Frozen Architecture Baseline)  
**Status Date:** 2026-08-27  

> **Legend:**  
> - 🟢 **PROVEN**: Implemented and verified via automated test suite.  
> - 🟡 **IN PROGRESS**: Specification defined, under active implementation.  
> - 🔴 **NOT PROVEN**: Specification defined, implementation or automated test not yet written.  

---

| # | Frozen Architecture Invariant (v11) | Implementation Control | Target Code Location | Target Automated Test | Conformance Status |
|---|---|---|---|---|---|
| **INV-01** | AI recommends; it does not execute | AI engine emits immutable `DecisionArtifact`; AI has no executor or provider access | `src/revenue_recovery/ai_decision/` | `tests/unit/test_ai_decision.py`, `tests/conformance/test_boundaries.py` | 🔴 **NOT PROVEN** |
| **INV-02** | Least-privilege authority boundaries | Separate service classes & interfaces; no shared god-objects | `src/revenue_recovery/` | `tests/conformance/test_authority_isolation.py` | 🔴 **NOT PROVEN** |
| **INV-03** | Capability-based Action Authorization | Cryptographically signed `ActionAuthorization` with TTL, amount, case, and channel | `src/revenue_recovery/safety/authorizer.py` | `tests/unit/test_authorizer.py`, `tests/security/test_token_tampering.py` | 🔴 **NOT PROVEN** |
| **INV-04** | Executor acts ONLY on valid signed token | Token signature, expiry, and scope validation before any execution call | `src/revenue_recovery/executor/executor.py` | `tests/unit/test_executor.py`, `tests/security/test_unsigned_execution_rejected.py` | 🔴 **NOT PROVEN** |
| **INV-05** | Strict MVP Sandbox Isolation | Egress allowlist validation; refusal of non-sandbox URIs & technical network isolation | `src/revenue_recovery/executor/sandbox_guard.py` | `tests/conformance/test_sandbox_isolation.py` | 🔴 **NOT PROVEN** |
| **INV-06** | Zero production credentials in MVP | Config validator & environment scanner fail startup if production API keys/URIs present | `src/revenue_recovery/foundation/config.py` | `tests/unit/test_config.py` | 🔴 **NOT PROVEN** |
| **INV-07** | Mandatory compliance obligations cannot be discarded | Deterministic Scheduler prioritizes mandatory disclosures over optional recovery | `src/revenue_recovery/governance/scheduler.py` | `tests/unit/test_compliance_scheduler.py` | 🔴 **NOT PROVEN** |
| **INV-08** | Multi-way obligation collision resolution | Deterministic precedence arbitration with legal safety fallbacks | `src/revenue_recovery/governance/scheduler.py` | `tests/unit/test_multiway_collisions.py` | 🔴 **NOT PROVEN** |
| **INV-09** | Safety freezes cannot be bypassed via retry | Frozen state in DB & Arbitrator rejects retries on safety trip | `src/revenue_recovery/governance/arbitrator.py` | `tests/unit/test_arbitrator_freeze.py` | 🔴 **NOT PROVEN** |
| **INV-10** | Incident obligations route through authoritative Scheduler | Common ingestion queue for incident obligations into Scheduler | `src/revenue_recovery/governance/scheduler.py` | `tests/integration/test_incident_scheduler_flow.py` | 🔴 **NOT PROVEN** |
| **INV-11** | Gross recovered $\neq$ Confirmed recovered | Two-stage revenue ledger requiring settlement reconciliation | `src/revenue_recovery/reconciliation/ledger.py` | `tests/unit/test_revenue_ledger.py` | 🔴 **NOT PROVEN** |
| **INV-12** | Dispute & chargeback financial tracking | Dispute webhooks adjust net confirmed revenue to negative/loss | `src/revenue_recovery/reconciliation/dispute_handler.py` | `tests/unit/test_disputes.py` | 🔴 **NOT PROVEN** |
| **INV-13** | Backtesting never presented as causal lift | Evidence Engine requires randomized controlled experiment logs | `src/revenue_recovery/evidence/evidence_engine.py` | `tests/unit/test_evidence_engine.py` | 🔴 **NOT PROVEN** |
| **INV-14** | Headline metrics cannot silently disappear | Evidence Registry enforces required reporting states & blocking reason codes | `src/revenue_recovery/evidence/metrics_registry.py` | `tests/unit/test_metrics_governance.py` | 🔴 **NOT PROVEN** |
| **INV-15** | Kill switch & circuit breaker fail-closed | Global & granular kill switch halts execution immediately | `src/revenue_recovery/safety/kill_switch.py` | `tests/unit/test_kill_switch.py` | 🔴 **NOT PROVEN** |
| **INV-16** | Idempotency across execution & retry | Enforced unique idempotency keys on authorizations & executions | `src/revenue_recovery/executor/idempotency.py` | `tests/unit/test_idempotency.py` | 🔴 **NOT PROVEN** |
| **INV-17** | Immutable Decision Artifacts with input snapshot hashes | SHA-256 canonical hashing of model inputs & immutable storage | `src/revenue_recovery/ai_decision/artifacts.py` | `tests/unit/test_decision_artifacts.py` | 🔴 **NOT PROVEN** |
| **INV-18** | Complete audit logging of financial transitions | Append-only audit logger for every state change & decision | `src/revenue_recovery/foundation/audit.py` | `tests/unit/test_audit_trail.py` | 🔴 **NOT PROVEN** |

---

## Conformance Summary
- **Total Invariants Mapped:** 18
- **PROVEN:** 0
- **IN PROGRESS:** 0
- **NOT PROVEN:** 18 (All invariants remain NOT PROVEN until full lifecycle implementation and end-to-end evidence are established)
