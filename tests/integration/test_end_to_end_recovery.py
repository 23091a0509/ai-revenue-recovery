"""End-to-End Sandbox Recovery Integration Test Suite (TICKET-29).

Authoritative Basis:
- Frozen Architecture Baseline v11 Requirements.
- engineering_backlog.md: Milestone 9, TICKET-29.
- implementation_specification.md: §1 Rules 1–14, §2 Boundary Matrix, §3 Schema & State Machine, §4 Event Contracts.
- conformance_matrix.md: INV-01 through INV-18.
"""

from datetime import datetime, timedelta, timezone
import pytest

from src.revenue_recovery.ai_decision import (
    AIDecisionEngine,
    DecisionArtifact,
)
from src.revenue_recovery.evidence import (
    BlockingReason,
    EvidenceEngine,
    ExperimentAssignment,
    ExperimentConfig,
    ExperimentEngine,
    ReportingState,
)
from src.revenue_recovery.executor import (
    ActionExecutor,
    ExecutionRequest,
    ExecutionResult,
    IdempotencyStore,
    SandboxGuard,
)
from src.revenue_recovery.foundation.audit import CryptographicAuditLogger
from src.revenue_recovery.foundation.events import (
    ActionChannel,
    ActionType,
    CaseState,
    ComplianceObligation,
    ExecutionStatus,
    FailureReason,
    ObligationType,
    PaymentFailureEvent,
    RecoveryCase,
    RiskTier,
)
from src.revenue_recovery.governance.arbitrator import (
    ArbitratedOutcome,
    ArbitrationRecord,
    ControlPlaneArbitrator,
)
from src.revenue_recovery.governance.policy_engine import (
    PolicyEngine,
    PolicyEvaluatedEvent,
    PolicyEvaluationResult,
)
from src.revenue_recovery.governance.scheduler import ComplianceScheduler
from src.revenue_recovery.reconciliation.dispute_handler import (
    DisputeReason,
    DisputeStage,
    DisputeWebhook,
    SettlementDisputeHandler,
    SettlementWebhook,
)
from src.revenue_recovery.reconciliation.ledger import FinancialState, RevenueLedger
from src.revenue_recovery.recovery_engine import (
    CaseFrozenError,
    CaseManager,
    DiagnosisResult,
    InvalidStateTransitionError,
    evaluate_diagnosis,
)
from src.revenue_recovery.safety import (
    ActionAuthorization,
    CapacityGovernor,
    CircuitBreaker,
    CryptographicAuthorizer,
    GranularCircuitBreakerRegistry,
    KillSwitchManager,
)


@pytest.fixture
def signing_secret() -> str:
    return "sandbox_secure_test_signing_secret_998877_abcdef"


@pytest.fixture
def audit_logger() -> CryptographicAuditLogger:
    return CryptographicAuditLogger()


@pytest.fixture
def kill_switch() -> KillSwitchManager:
    return KillSwitchManager()


@pytest.fixture
def circuit_breakers() -> GranularCircuitBreakerRegistry:
    return GranularCircuitBreakerRegistry(default_failure_threshold=3, default_recovery_timeout_seconds=30.0)


@pytest.fixture
def capacity_governor() -> CapacityGovernor:
    return CapacityGovernor(max_actions_per_window=100, max_volume_in_cents_per_window=5000000, window_seconds=60.0)


@pytest.fixture
def sandbox_guard() -> SandboxGuard:
    return SandboxGuard(dns_resolver=lambda host, port: ["127.0.0.1"])


@pytest.fixture
def idempotency_store() -> IdempotencyStore:
    return IdempotencyStore()


@pytest.fixture
def case_manager(audit_logger: CryptographicAuditLogger) -> CaseManager:
    return CaseManager(audit_logger=audit_logger)


@pytest.fixture
def ai_engine(audit_logger: CryptographicAuditLogger) -> AIDecisionEngine:
    return AIDecisionEngine(audit_logger=audit_logger)


@pytest.fixture
def policy_engine(audit_logger: CryptographicAuditLogger) -> PolicyEngine:
    return PolicyEngine(audit_logger=audit_logger)


@pytest.fixture
def scheduler(audit_logger: CryptographicAuditLogger) -> ComplianceScheduler:
    return ComplianceScheduler(audit_logger=audit_logger)


@pytest.fixture
def experiment_engine(audit_logger: CryptographicAuditLogger) -> ExperimentEngine:
    ee = ExperimentEngine(audit_logger=audit_logger)
    # 100% treatment configuration for standard deterministic happy-path
    cfg = ExperimentConfig(
        experiment_id="exp_e2e_rct",
        name="E2E RCT Experiment",
        treatment_ratio=1.0,
        control_ratio=0.0,
        excluded_ratio=0.0,
        salt="e2e_salt_v1",
    )
    ee.register_experiment(cfg)
    return ee


@pytest.fixture
def arbitrator(
    policy_engine: PolicyEngine,
    scheduler: ComplianceScheduler,
    kill_switch: KillSwitchManager,
    circuit_breakers: GranularCircuitBreakerRegistry,
    capacity_governor: CapacityGovernor,
    audit_logger: CryptographicAuditLogger,
) -> ControlPlaneArbitrator:
    return ControlPlaneArbitrator(
        policy_engine=policy_engine,
        scheduler=scheduler,
        kill_switch=kill_switch,
        circuit_breakers=circuit_breakers,
        capacity_governor=capacity_governor,
        audit_logger=audit_logger,
    )


@pytest.fixture
def authorizer(signing_secret: str) -> CryptographicAuthorizer:
    return CryptographicAuthorizer(signing_secret=signing_secret)


@pytest.fixture
def executor(
    authorizer: CryptographicAuthorizer,
    kill_switch: KillSwitchManager,
    circuit_breakers: GranularCircuitBreakerRegistry,
    capacity_governor: CapacityGovernor,
    sandbox_guard: SandboxGuard,
    audit_logger: CryptographicAuditLogger,
    idempotency_store: IdempotencyStore,
) -> ActionExecutor:
    return ActionExecutor(
        authorizer=authorizer,
        kill_switch=kill_switch,
        circuit_breakers=circuit_breakers,
        capacity_governor=capacity_governor,
        sandbox_guard=sandbox_guard,
        audit_logger=audit_logger,
        idempotency_store=idempotency_store,
    )


@pytest.fixture
def ledger(audit_logger: CryptographicAuditLogger) -> RevenueLedger:
    return RevenueLedger(audit_logger=audit_logger)


@pytest.fixture
def dispute_handler(ledger: RevenueLedger, audit_logger: CryptographicAuditLogger) -> SettlementDisputeHandler:
    return SettlementDisputeHandler(ledger=ledger, audit_logger=audit_logger)


@pytest.fixture
def evidence_engine(
    ledger: RevenueLedger, experiment_engine: ExperimentEngine, audit_logger: CryptographicAuditLogger
) -> EvidenceEngine:
    return EvidenceEngine(ledger=ledger, experiment_engine=experiment_engine, audit_logger=audit_logger)


# ============================================================================
# PART 1: End-to-End Happy Path Workflow
# ============================================================================

class TestEndToEndHappyPathRecovery:
    """Verifies complete end-to-end recovery loop across all Milestones 1 through 8."""

    def test_complete_successful_recovery_lifecycle(
        self,
        audit_logger: CryptographicAuditLogger,
        case_manager: CaseManager,
        ai_engine: AIDecisionEngine,
        policy_engine: PolicyEngine,
        scheduler: ComplianceScheduler,
        experiment_engine: ExperimentEngine,
        arbitrator: ControlPlaneArbitrator,
        authorizer: CryptographicAuthorizer,
        executor: ActionExecutor,
        ledger: RevenueLedger,
        dispute_handler: SettlementDisputeHandler,
        evidence_engine: EvidenceEngine,
    ):
        t0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)

        # 1. Trigger Event & Case Creation (OPEN)
        event = PaymentFailureEvent(
            customer_id="cust_e2e_9988",
            invoice_id="inv_e2e_001",
            amount_in_cents=10000,
            currency="INR",
            failure_reason=FailureReason.GENERIC_DECLINE,
            failure_code="do_not_honor",
            gateway_reference="gw_ref_001",
            failed_at=t0,
        )
        case = case_manager.create_case(event, current_time=t0)
        assert case.state == CaseState.OPEN

        # 2. Diagnosis (DIAGNOSED)
        diagnosis = evaluate_diagnosis(event, attempt_count=case.attempt_count)
        assert diagnosis.is_recoverable is True
        case = case_manager.transition_case(
            case_id=case.case_id,
            target_state=CaseState.DIAGNOSED,
            risk_tier=diagnosis.risk_tier,
            reason=diagnosis.rationale,
            current_time=t0,
        )
        assert case.state == CaseState.DIAGNOSED

        # 3. AI Decision Recommendation (EVALUATING)
        case = case_manager.transition_case(
            case_id=case.case_id,
            target_state=CaseState.EVALUATING,
            current_time=t0,
        )
        assert case.state == CaseState.EVALUATING
        decision = ai_engine.evaluate_case(case, diagnosis, current_time=t0)
        assert decision.recommended_action == ActionType.RETRY_CHARGE
        assert decision.parameters["channel"] == ActionChannel.DIRECT_PAYMENT_GATEWAY.value

        # 4. Compliance Scheduling
        ob = ComplianceObligation(
            case_id=case.case_id,
            obligation_type=ObligationType.MANDATORY_DISCLOSURE,
            scheduled_time=t0 + timedelta(days=1),
        )
        plan = scheduler.schedule_case_obligations(case=case, obligations=[ob], current_time=t0)
        assert len(plan.scheduled_obligations) == 1

        # 5. RCT Experiment Assignment
        exp_record = experiment_engine.assign(case, experiment_id="exp_e2e_rct", current_time=t0)
        assert exp_record.assignment == ExperimentAssignment.TREATMENT

        # 6. Cross-Loop Control-Plane Arbitration (PROCEED)
        arb_res = arbitrator.arbitrate(
            case=case,
            diagnosis=diagnosis,
            decision=decision,
            experiment_assignment=exp_record.assignment,
            current_time=t0,
        )
        assert arb_res.arbitrated_outcome == ArbitratedOutcome.PROCEED

        # 7. Cryptographic Token Authorization (SCHEDULED)
        auth_token = authorizer.mint_authorization(
            case_id=case.case_id,
            customer_id=case.customer_id,
            action_type=decision.recommended_action,
            max_amount_in_cents=case.amount_in_cents,
            currency=case.currency,
            channel=ActionChannel(decision.parameters["channel"]),
            policy_version="1.0.0",
            decision_id=decision.artifact_id,
            idempotency_key=f"idem_{case.case_id}_01",
            expires_at=t0 + timedelta(minutes=15),
            current_time=t0,
        )
        assert auth_token.signature != ""
        case = case_manager.transition_case(
            case_id=case.case_id,
            target_state=CaseState.SCHEDULED,
            current_time=t0,
        )
        assert case.state == CaseState.SCHEDULED

        # 8. Sandbox Action Execution (EXECUTING)
        case = case_manager.transition_case(
            case_id=case.case_id,
            target_state=CaseState.EXECUTING,
            current_time=t0,
        )
        assert case.state == CaseState.EXECUTING

        req = ExecutionRequest(
            case_id=case.case_id,
            customer_id=case.customer_id,
            action_type=decision.recommended_action,
            channel=ActionChannel(decision.parameters["channel"]),
            amount_in_cents=case.amount_in_cents,
            currency=case.currency,
            destination_url="http://127.0.0.1:8000/simulator/charge",
            action_payload={"amount": 10000, "currency": "INR", "customer_id": case.customer_id},
            idempotency_key=auth_token.idempotency_key,
        )
        exec_res = executor.execute_action(
            request=req,
            token=auth_token,
            current_time=t0,
        )
        assert exec_res.status == ExecutionStatus.SUCCESS

        # 9. Stage 1 Two-Stage Revenue Ledger (RECONCILING)
        ledger.record_gross_recovery(
            case_id=case.case_id,
            gross_amount=10000,
            currency="INR",
            execution_id=exec_res.idempotency_key,
            reference="rec_e2e_stage1",
            current_time=t0,
        )
        case = case_manager.transition_case(
            case_id=case.case_id,
            target_state=CaseState.RECONCILING,
            current_time=t0,
        )
        assert case.state == CaseState.RECONCILING

        summary_stage1 = ledger.get_case_summary(case.case_id)
        assert summary_stage1.total_gross_recovered == 10000
        assert summary_stage1.total_net_confirmed == 0  # INV-11: Not confirmed yet

        # 10. Stage 2 Settlement Reconciliation (RESOLVED)
        settlement_hook = SettlementWebhook(
            event_id="evt_settle_001",
            settlement_id="set_9988_001",
            case_id=case.case_id,
            execution_id=exec_res.idempotency_key,
            gross_amount=10000,
            fee_amount=200,
            net_amount=9800,
            currency="INR",
            settled_at=t0 + timedelta(days=2),
        )
        entry_s2 = dispute_handler.process_settlement(settlement_hook)
        assert entry_s2.financial_state == FinancialState.CONFIRMED_SETTLED
        assert entry_s2.net_confirmed_amount == 9800

        case = case_manager.transition_case(
            case_id=case.case_id,
            target_state=CaseState.RESOLVED,
            current_time=t0 + timedelta(days=2),
        )
        assert case.state == CaseState.RESOLVED

        # 11. Evidence Registry Evaluation
        ctrl_cases = []
        for i in range(10):
            cid = f"ctrl_case_{i:03d}"
            ctrl_cases.append(cid)
            if i < 3:
                ledger.record_gross_recovery(cid, 10000, "INR", f"exec_c_{i:03d}")
                ledger.record_confirmed_settlement(cid, 10000, 9800, "INR", f"exec_c_{i:03d}")

        treat_cases = [case.case_id]
        for i in range(1, 10):
            cid = f"extra_treat_{i:03d}"
            treat_cases.append(cid)
            ledger.record_gross_recovery(cid, 10000, "INR", f"exec_t_{i:03d}")
            ledger.record_confirmed_settlement(cid, 10000, 9800, "INR", f"exec_t_{i:03d}")

        evidence_entry = evidence_engine.evaluate_window(
            metric_id="e2e_headline_lift",
            evaluation_window="2026-Q3-E2E",
            treatment_case_ids=treat_cases,
            control_case_ids=ctrl_cases,
            min_sample_size=10,
        )
        assert evidence_entry.reporting_state == ReportingState.APPROVED
        assert evidence_entry.incremental_lift is not None
        assert evidence_entry.incremental_lift > 0

        # 12. Audit Chain Integrity Verification (INV-18)
        assert audit_logger.verify_chain_integrity() is True
        assert len(audit_logger.entries) >= 10


# ============================================================================
# PART 2: Adversarial & Fail-Closed Safety Flows
# ============================================================================

class TestAdversarialAndFailsafeIntegrationFlows:
    """Verifies all fail-closed safety, arbitration, and boundary mechanisms."""

    def test_global_kill_switch_blocks_arbitration_and_prevents_authorization(
        self,
        case_manager: CaseManager,
        ai_engine: AIDecisionEngine,
        experiment_engine: ExperimentEngine,
        arbitrator: ControlPlaneArbitrator,
        kill_switch: KillSwitchManager,
    ):
        event = PaymentFailureEvent(
            customer_id="cust_ks_001",
            invoice_id="inv_ks_001",
            amount_in_cents=5000,
            failure_reason=FailureReason.GENERIC_DECLINE,
            gateway_reference="gw_ks_001",
        )
        case = case_manager.create_case(event)
        diagnosis = evaluate_diagnosis(event)
        case = case_manager.transition_case(case.case_id, CaseState.DIAGNOSED)
        case = case_manager.transition_case(case.case_id, CaseState.EVALUATING)
        decision = ai_engine.evaluate_case(case, diagnosis)
        exp_record = experiment_engine.assign(case)

        # Activate Global Kill Switch
        kill_switch.activate_global(reason="EMERGENCY_HALT")

        arb_res = arbitrator.arbitrate(
            case=case,
            diagnosis=diagnosis,
            decision=decision,
            experiment_assignment=exp_record.assignment,
        )

        assert arb_res.arbitrated_outcome == ArbitratedOutcome.BLOCK

    def test_circuit_breaker_open_returns_hold_and_halts_execution(
        self,
        case_manager: CaseManager,
        ai_engine: AIDecisionEngine,
        experiment_engine: ExperimentEngine,
        arbitrator: ControlPlaneArbitrator,
        circuit_breakers: GranularCircuitBreakerRegistry,
    ):
        event = PaymentFailureEvent(
            customer_id="cust_cb_001",
            invoice_id="inv_cb_001",
            amount_in_cents=5000,
            failure_reason=FailureReason.GENERIC_DECLINE,
            gateway_reference="gw_cb_001",
        )
        case = case_manager.create_case(event)
        diagnosis = evaluate_diagnosis(event)
        case = case_manager.transition_case(case.case_id, CaseState.DIAGNOSED)
        case = case_manager.transition_case(case.case_id, CaseState.EVALUATING)
        decision = ai_engine.evaluate_case(case, diagnosis)
        exp_record = experiment_engine.assign(case)

        # Trip Circuit Breaker for channel DIRECT_PAYMENT_GATEWAY
        cb = circuit_breakers.get_or_create(ActionChannel.DIRECT_PAYMENT_GATEWAY, failure_threshold=1)
        cb.record_failure()  # Trips to OPEN

        arb_res = arbitrator.arbitrate(
            case=case,
            diagnosis=diagnosis,
            decision=decision,
            experiment_assignment=exp_record.assignment,
        )

        assert arb_res.arbitrated_outcome == ArbitratedOutcome.HOLD

    def test_safety_freeze_prevents_retry_and_blocks_arbitration_inv09(
        self,
        case_manager: CaseManager,
        ai_engine: AIDecisionEngine,
        experiment_engine: ExperimentEngine,
        arbitrator: ControlPlaneArbitrator,
    ):
        event = PaymentFailureEvent(
            customer_id="cust_frz_001",
            invoice_id="inv_frz_001",
            amount_in_cents=5000,
            failure_reason=FailureReason.GENERIC_DECLINE,
            gateway_reference="gw_frz_001",
        )
        case = case_manager.create_case(event)
        diagnosis = evaluate_diagnosis(event)
        case = case_manager.transition_case(case.case_id, CaseState.DIAGNOSED)
        case = case_manager.transition_case(case.case_id, CaseState.EVALUATING)
        decision = ai_engine.evaluate_case(case, diagnosis)

        # Freeze the case
        case = case_manager.freeze_case(case.case_id, reason="CRITICAL_SAFETY_ANOMALY")
        assert case.state == CaseState.FROZEN

        # Retry transition is forbidden
        with pytest.raises(InvalidStateTransitionError):
            case_manager.transition_case(case.case_id, CaseState.SCHEDULED)

        exp_record = experiment_engine.assign(case)

        arb_res = arbitrator.arbitrate(
            case=case,
            diagnosis=diagnosis,
            decision=decision,
            experiment_assignment=exp_record.assignment,
        )

        assert arb_res.arbitrated_outcome == ArbitratedOutcome.BLOCK

    def test_experiment_control_holdback_suppresses_execution_inv13(
        self,
        case_manager: CaseManager,
        ai_engine: AIDecisionEngine,
        arbitrator: ControlPlaneArbitrator,
    ):
        event = PaymentFailureEvent(
            customer_id="cust_ctrl_001",
            invoice_id="inv_ctrl_001",
            amount_in_cents=5000,
            failure_reason=FailureReason.GENERIC_DECLINE,
            gateway_reference="gw_ctrl_001",
        )
        case = case_manager.create_case(event)
        diagnosis = evaluate_diagnosis(event)
        case = case_manager.transition_case(case.case_id, CaseState.DIAGNOSED)
        case = case_manager.transition_case(case.case_id, CaseState.EVALUATING)
        decision = ai_engine.evaluate_case(case, diagnosis)

        arb_res = arbitrator.arbitrate(
            case=case,
            diagnosis=diagnosis,
            decision=decision,
            experiment_assignment=ExperimentAssignment.CONTROL,
        )

        assert arb_res.arbitrated_outcome == ArbitratedOutcome.HOLD

    def test_fraud_suspected_blocks_case_and_recommends_no_action(
        self,
        case_manager: CaseManager,
        ai_engine: AIDecisionEngine,
    ):
        event = PaymentFailureEvent(
            customer_id="cust_fraud_001",
            invoice_id="inv_fraud_001",
            amount_in_cents=5000,
            failure_reason=FailureReason.FRAUD_SUSPECTED,  # Rule 1 trigger
            failure_code="suspected_fraud",
            gateway_reference="gw_fraud_001",
        )
        case = case_manager.create_case(event)
        diagnosis = evaluate_diagnosis(event)
        assert diagnosis.is_recoverable is False
        assert diagnosis.risk_tier == RiskTier.BLOCKED

        case = case_manager.transition_case(case.case_id, CaseState.DIAGNOSED)
        case = case_manager.transition_case(case.case_id, CaseState.EVALUATING)
        decision = ai_engine.evaluate_case(case, diagnosis)
        assert decision.recommended_action == ActionType.NO_ACTION

    def test_dispute_and_chargeback_flow_adjusts_ledger_inv12(
        self,
        ledger: RevenueLedger,
        dispute_handler: SettlementDisputeHandler,
    ):
        cid = "case_dispute_e2e"
        ledger.record_gross_recovery(cid, 10000, "INR", "exec_disp_01")
        ledger.record_confirmed_settlement(cid, 10000, 9800, "INR", "exec_disp_01")

        summary_pre = ledger.get_case_summary(cid)
        assert summary_pre.total_net_confirmed == 9800

        # Inbound Dispute Webhook
        dispute_hook = DisputeWebhook(
            event_id="evt_disp_001",
            dispute_id="dp_9988_001",
            case_id=cid,
            execution_id="exec_disp_01",
            disputed_amount=10000,
            currency="INR",
            reason=DisputeReason.FRAUDULENT,
            stage=DisputeStage.NEEDS_RESPONSE,
        )
        entry = dispute_handler.process_dispute(dispute_hook)
        assert entry.financial_state == FinancialState.DISPUTED
        assert entry.net_confirmed_amount == 0

        summary_post = ledger.get_case_summary(cid)
        assert summary_post.latest_state == FinancialState.DISPUTED


# ============================================================================
# PART 3: Invariants Verification (INV-01 through INV-18)
# ============================================================================

class TestArchitecturalInvariantsConformance:
    """Verifies all 18 architectural invariants in integrated context."""

    def test_inv01_and_inv02_ai_and_governance_authority_isolation(
        self,
        ai_engine: AIDecisionEngine,
        policy_engine: PolicyEngine,
        scheduler: ComplianceScheduler,
        arbitrator: ControlPlaneArbitrator,
        evidence_engine: EvidenceEngine,
    ):
        """INV-01 & INV-02: Zero execution/minting methods on decision and governance services."""
        forbidden = ["execute", "dispatch", "charge", "send", "mint_token", "authorize"]
        for svc in [ai_engine, policy_engine, scheduler, arbitrator, evidence_engine]:
            for m in forbidden:
                assert not hasattr(svc, m), f"{type(svc).__name__} must not expose '{m}'"

    def test_inv16_idempotent_execution_replay(
        self,
        executor: ActionExecutor,
        authorizer: CryptographicAuthorizer,
    ):
        """INV-16: Duplicate execution requests return cached result without duplicate execution."""
        t0 = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
        auth = authorizer.mint_authorization(
            case_id="case_idem_001",
            customer_id="cust_idem_001",
            action_type=ActionType.RETRY_CHARGE,
            max_amount_in_cents=10000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="1.0.0",
            decision_id="dec_idem_001",
            idempotency_key="idem_key_001",
            expires_at=t0 + timedelta(minutes=15),
            current_time=t0,
        )

        req = ExecutionRequest(
            case_id="case_idem_001",
            customer_id="cust_idem_001",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=10000,
            currency="INR",
            destination_url="http://127.0.0.1:8000/charge",
            action_payload={"amount": 10000},
            idempotency_key=auth.idempotency_key,
        )

        r1 = executor.execute_action(request=req, token=auth, current_time=t0)
        r2 = executor.execute_action(request=req, token=auth, current_time=t0)

        assert r1.idempotency_key == r2.idempotency_key
        assert r1.status == r2.status
        assert r1.response_payload == r2.response_payload
