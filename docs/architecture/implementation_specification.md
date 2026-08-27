# AI Revenue Recovery — Implementation Specification
**Document Version:** 1.0.0  
**Baseline:** Implementation Plan v11 (Frozen Architecture Baseline)  
**Status:** DRAFT / APPROVED FOR SPECIFICATION ONLY (NO CODE IMPLEMENTED YET)

---

## 1. Executive Summary & Architectural Invariants

This specification operationalizes the Frozen Architecture Baseline v11 for the **AI Revenue Recovery MVP**. The MVP proves the end-to-end recovery loop in a strictly isolated sandbox environment for payment-failure recovery without live money movement or customer contact.

### 14 Non-Negotiable Rules
1. **AI recommends; it does not execute.**
2. **No service receives authority it does not need.**
3. **The Executor acts only on valid, bounded Authorization tokens.**
4. **MVP must remain completely isolated from production payment and messaging systems.**
5. **No production credentials, production endpoints, or production network paths may exist in the MVP environment.**
6. **Mandatory compliance obligations cannot be silently discarded.**
7. **Safety freezes cannot be bypassed through retries.**
8. **Incident-generated obligations must use the same authoritative Compliance Scheduler.**
9. **Recovered revenue must not automatically be treated as confirmed revenue.**
10. **Backtesting must never be presented as causal lift.**
11. **Headline metrics must not silently disappear.**
12. **Every critical architecture invariant must map to an implementation control AND an automated test.**
13. **Production READY is revocable and expires.**
14. **No script, side repository, pilot account, credential, manual configuration, or integration may bypass the production-readiness boundary.**

---

## 2. Service Decomposition & Boundary Matrix

| Component | Read Access | Decision Role | Authorize Role | Execute Role | Network Egress |
|---|---|---|---|---|---|
| **Foundation / Contracts** | Shared schemas | None | None | None | None |
| **Recovery Engine** | Events, Cases, History | Ingestion, Risk score, Diagnosis | No | No | Internal DB only |
| **AI Decision Engine** | Case context, Diagnosis snapshot | Recommendations only (immutable Decision Artifact) | No | No | Isolated LLM Provider only |
| **Policy Engine** | Policies, Rules, Decision Artifact | Policy compliance determination | No | No | Internal DB only |
| **Compliance Scheduler** | Obligations, Constraints, Calendar | Deterministic obligation scheduling & collision handling | No | No | Internal DB only |
| **Control-Plane Arbitrator**| Safety state, Capacity, Experiment state | Cross-loop arbitration & prioritization | No | No | Internal DB only |
| **Authorization Service** | Approved Decision + Arbitration | None | Yes (Mints signed `ActionAuthorization`) | No | Internal DB / Key vault |
| **Action Executor** | Signed `ActionAuthorization` | None | No | Yes (Calls Sandbox Simulator ONLY) | Sandbox Simulators ONLY |
| **Reconciliation & Ledger** | Settlement/Dispute webhooks | Financial state reconciliation | No | No | Internal DB only |
| **Evidence & Experiment Engine**| Ledger, Cases, Experiment splits | Causal lift & reporting state calculation | No | No | Internal DB only |

---

## 3. Database & Schema Design

All tables maintain strict auditability with append-only event streams and immutable artifact snapshots.

```sql
-- 1. Recovery Cases
CREATE TABLE recovery_cases (
    case_id VARCHAR(64) PRIMARY KEY,
    customer_id VARCHAR(64) NOT NULL,
    trigger_event_id VARCHAR(64) NOT NULL,
    amount_in_cents BIGINT NOT NULL,
    currency VARCHAR(3) NOT NULL DEFAULT 'INR',
    state VARCHAR(32) NOT NULL, -- OPEN, DIAGNOSED, EVALUATING, SCHEDULED, EXECUTING, RECONCILING, RESOLVED, ABANDONED, FROZEN
    risk_tier VARCHAR(16) NOT NULL, -- LOW, MEDIUM, HIGH, BLOCKED
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- 2. Immutable Decision Artifacts
CREATE TABLE decision_artifacts (
    artifact_id VARCHAR(64) PRIMARY KEY,
    case_id VARCHAR(64) NOT NULL REFERENCES recovery_cases(case_id),
    model_version VARCHAR(64) NOT NULL,
    prompt_version VARCHAR(64) NOT NULL,
    tool_schema_version VARCHAR(64) NOT NULL,
    canonical_input_hash VARCHAR(64) NOT NULL,
    input_snapshot JSONB NOT NULL,
    recommended_action VARCHAR(64) NOT NULL,
    parameters JSONB NOT NULL,
    confidence_score NUMERIC(5,4) NOT NULL,
    reasoning_summary TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- 3. Policy Registry & Versions
CREATE TABLE policies (
    policy_id VARCHAR(64) NOT NULL,
    version VARCHAR(32) NOT NULL,
    lifecycle_state VARCHAR(32) NOT NULL, -- DRAFT, REVIEW, TEST, SIMULATE, APPROVED, STAGE, PRODUCTION, RETIRED
    rules_definition JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    approved_by VARCHAR(64),
    PRIMARY KEY (policy_id, version)
);

-- 4. Scheduled Obligations
CREATE TABLE compliance_obligations (
    obligation_id VARCHAR(64) PRIMARY KEY,
    case_id VARCHAR(64) NOT NULL REFERENCES recovery_cases(case_id),
    obligation_type VARCHAR(64) NOT NULL, -- MANDATORY_DISCLOSURE, COOLING_OFF, RETRY_WINDOW, CONSENT_CHECK
    is_mandatory BOOLEAN NOT NULL DEFAULT TRUE,
    scheduled_time TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(32) NOT NULL, -- PENDING, SATISFIED, COLLISION_RESOLVED, EXPIRED, FROZEN
    resolution_reason TEXT
);

-- 5. Control-Plane Arbitrator Decisions
CREATE TABLE arbitration_records (
    arbitration_id VARCHAR(64) PRIMARY KEY,
    case_id VARCHAR(64) NOT NULL REFERENCES recovery_cases(case_id),
    decision_artifact_id VARCHAR(64) NOT NULL REFERENCES decision_artifacts(artifact_id),
    safety_verdict VARCHAR(32) NOT NULL, -- PASS, CIRCUIT_BROKEN, KILL_SWITCH_ACTIVE, CAPACITY_EXCEEDED
    compliance_verdict VARCHAR(32) NOT NULL, -- APPROVED, BLOCKED, DEFERRED
    experiment_assignment VARCHAR(32) NOT NULL, -- TREATMENT, CONTROL, EXCLUDED
    arbitrated_outcome VARCHAR(32) NOT NULL, -- PROCEED, BLOCK, DEFER, HOLD
    arbitration_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- 6. Bounded Authorizations
CREATE TABLE action_authorizations (
    authorization_id VARCHAR(64) PRIMARY KEY,
    case_id VARCHAR(64) NOT NULL REFERENCES recovery_cases(case_id),
    action_type VARCHAR(64) NOT NULL,
    customer_id VARCHAR(64) NOT NULL,
    max_amount_in_cents BIGINT NOT NULL,
    currency VARCHAR(3) NOT NULL,
    channel VARCHAR(32) NOT NULL,
    policy_version VARCHAR(32) NOT NULL,
    decision_id VARCHAR(64) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    idempotency_key VARCHAR(128) UNIQUE NOT NULL,
    signature VARCHAR(512) NOT NULL,
    status VARCHAR(32) NOT NULL, -- ISSUED, CONSUMED, EXPIRED, REVOKED
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- 7. Executed Actions (Sandbox Only)
CREATE TABLE execution_records (
    execution_id VARCHAR(64) PRIMARY KEY,
    authorization_id VARCHAR(64) NOT NULL REFERENCES action_authorizations(authorization_id),
    case_id VARCHAR(64) NOT NULL REFERENCES recovery_cases(case_id),
    target_endpoint VARCHAR(256) NOT NULL, -- Must match regex '^https?://sandbox-.*'
    request_payload JSONB NOT NULL,
    response_payload JSONB NOT NULL,
    http_status INT NOT NULL,
    status VARCHAR(32) NOT NULL, -- SUCCESS, FAILED, TIMEOUT
    executed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- 8. Immutable Revenue Ledger
CREATE TABLE revenue_ledger (
    entry_id VARCHAR(64) PRIMARY KEY,
    case_id VARCHAR(64) NOT NULL REFERENCES recovery_cases(case_id),
    execution_id VARCHAR(64) REFERENCES execution_records(execution_id),
    financial_state VARCHAR(32) NOT NULL, -- INITIATED, GROSS_RECOVERED, CONFIRMED_SETTLED, DISPUTED, REFUNDED, WRITTEN_OFF
    gross_amount BIGINT NOT NULL,
    net_confirmed_amount BIGINT NOT NULL DEFAULT 0,
    currency VARCHAR(3) NOT NULL,
    reconciliation_reference VARCHAR(128) NOT NULL,
    recorded_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- 9. Evidence Registry
CREATE TABLE evidence_registry (
    metric_id VARCHAR(64) NOT NULL,
    evaluation_window VARCHAR(64) NOT NULL,
    reporting_state VARCHAR(32) NOT NULL, -- APPROVED, EXPERIMENTAL, DIRECTIONAL, NOT_REPORTABLE, DATA_PENDING
    gross_recovered BIGINT NOT NULL,
    confirmed_recovered BIGINT NOT NULL,
    incremental_lift NUMERIC(8,4),
    blocking_reasons TEXT[],
    provenance_hash VARCHAR(64) NOT NULL,
    computed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (metric_id, evaluation_window)
);
```

---

## 4. Event Contracts

All domain events are strongly typed using Pydantic schemas:
- `RevenueRiskEvent`: `{ event_id, customer_id, failure_code, amount, currency, timestamp, idempotency_key }`
- `CaseDiagnosedEvent`: `{ case_id, diagnosis_code, risk_score, recommended_channel }`
- `DecisionArtifactCreatedEvent`: `{ artifact_id, case_id, canonical_input_hash, model_version, recommended_action }`
- `PolicyEvaluatedEvent`: `{ case_id, policy_version, is_allowed, violated_rules }`
- `ArbitrationEvaluatedEvent`: `{ case_id, arbitration_id, verdict, experiment_state }`
- `AuthorizationMintedEvent`: `{ authorization_id, case_id, token, expires_at, idempotency_key }`
- `ActionExecutedEvent`: `{ execution_id, authorization_id, simulator_response, success }`
- `SettlementReconciledEvent`: `{ case_id, settlement_id, net_amount, state }`
- `EvidenceCalculatedEvent`: `{ window_id, reporting_state, confirmed_recovered, lift }`

---

## 5. State Machines

### 5.1 Case Lifecycle
```
[TRIGGER_RECEIVED] ──► OPEN ──► DIAGNOSING ──► DIAGNOSED
                                                 │
                                                 ▼
[FROZEN / ABANDONED] ◄── [SAFETY_TRIP] ◄── EVALUATING (Policy + Scheduler + Arbitrator)
                                                 │ (Passed)
                                                 ▼
RESOLVED / RECONCILED ◄── RECONCILING ◄── EXECUTING ◄── AUTHORIZED
```

### 5.2 Policy Lifecycle
```
DRAFT ──► REVIEW ──► TEST ──► SIMULATE ──► APPROVED ──► STAGE ──► PRODUCTION ──► RETIRED
```

### 5.3 Financial Recovery State Machine
```
ATTEMPTED ──► GROSS_RECOVERED (Pending Settlement) ──► CONFIRMED_SETTLED
                     │                                         │
                     ▼                                         ▼
                 DISPUTED ─────────────────────────────► LOSS_RECORDED
```

---

## 6. Capability-Based Security & Authorization Model

### 6.1 Cryptographic Authorization Token
The Authorization Service is the sole authority holding the ECDSA private key (or HMAC secret in sandbox tests) to mint `ActionAuthorization` tokens.

**Token Payload:**
```json
{
  "auth_id": "auth-uuid-v4",
  "case_id": "case-uuid-v4",
  "action_type": "SANDBOX_PAYMENT_RETRY",
  "customer_id": "cust-98765",
  "max_amount_cents": 49900,
  "currency": "INR",
  "channel": "SANDBOX_GATEWAY",
  "policy_version": "v1.2.0",
  "decision_id": "art-uuid-v4",
  "expires_at": "2026-08-27T14:30:00Z",
  "idempotency_key": "idem-case-98765-attempt-1",
  "signature": "MEQCIF..."
}
```

### 6.2 Executor Invariants
- If token signature is invalid $\rightarrow$ Reject with `ERR_UNAUTHORIZED`.
- If token timestamp `expires_at < current_time` $\rightarrow$ Reject with `ERR_TOKEN_EXPIRED`.
- If requested amount > `max_amount_cents` $\rightarrow$ Reject with `ERR_AMOUNT_EXCEEDED`.
- If requested endpoint does NOT match `^https?://sandbox-.*` or localhost simulator $\rightarrow$ Reject with `ERR_ILLEGAL_NETWORK_DESTINATION`.
- If idempotency key was already consumed $\rightarrow$ Return recorded outcome without re-execution.

---

## 7. Sandbox Isolation & Boundary Specification

1. **No Production Credentials**: Zero production API keys, secrets, or endpoints in `.env` or configurations.
2. **Mock Payment & Messaging Simulators**: Dedicated local mock endpoints simulating 200 Success, 402 Insufficient Funds, 504 Gateway Timeout, and chargeback dispute lifecycles.
3. **Network Egress Firewall Rule**: Action Executor is hard-coded / configured to refuse any outbound URI not matching sandbox allowlist.

---

## 8. Definition of Done (DoD) for Implementation Milestones

Every milestone must satisfy:
1. **Source Code**: Implemented strictly against this specification in small modular units.
2. **Tests**: Unit tests, state-machine tests, negative security tests, and architecture conformance tests.
3. **Zero Invariant Weakening**: No safety controls bypassed to make tests pass.
4. **Evidence**: Full test execution logs captured.
5. **Git Commit**: Atomic commit with explicit description of v11 requirements implemented and remaining backlog.
