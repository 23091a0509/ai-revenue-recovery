"""Full Automated Architecture Conformance Test Suite (TICKET-30).

Authoritative Basis:
- Frozen Architecture Baseline v11 Requirements.
- engineering_backlog.md: Milestone 9, TICKET-30.
- conformance_matrix.md: Complete formal verification of Invariants INV-01 through INV-18.
- implementation_specification.md: §1 Rules 1–14, §2 Boundary Matrix, §3 Schema & State Machine, §4 Event Contracts.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import pytest

from src.revenue_recovery.ai_decision import (
    AIDecisionEngine,
    DecisionArtifact,
    compute_canonical_input_hash,
)
from src.revenue_recovery.evidence import (
    BlockingReason,
    EvidenceEngine,
    EvidenceMetricEntry,
    ExperimentAssignment,
    ExperimentConfig,
    ExperimentEngine,
    ReportingState,
)
from src.revenue_recovery.executor import (
    ActionExecutor,
    ExecutionRequest,
    ExecutionResult,
    IdempotencyConflictError,
    IdempotencyStore,
    SandboxGuard,
    SandboxViolationError,
)
from src.revenue_recovery.foundation.audit import CryptographicAuditLogger
from src.revenue_recovery.foundation.config import (
    FORBIDDEN_PRODUCTION_DOMAINS,
    AppSettings,
    ProductionBoundaryViolationError,
    get_settings,
    reset_cached_settings,
)
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
    ComplianceVerdict,
    ControlPlaneArbitrator,
    SafetyVerdict,
)
from src.revenue_recovery.governance.policy_engine import (
    PolicyEngine,
    PolicyEvaluatedEvent,
    PolicyEvaluationResult,
)
from src.revenue_recovery.governance.scheduler import (
    ComplianceScheduler,
    ObligationStatus,
    ScheduledObligationPlan,
)
from src.revenue_recovery.reconciliation.dispute_handler import (
    DisputeReason,
    DisputeStage,
    DisputeWebhook,
    SettlementDisputeHandler,
    SettlementWebhook,
)
from src.revenue_recovery.reconciliation.ledger import (
    FinancialState,
    LedgerSummary,
    RevenueLedger,
    RevenueLedgerEntry,
)
from src.revenue_recovery.recovery_engine import (
    CaseFrozenError,
    CaseManager,
    DiagnosisResult,
    InvalidStateTransitionError,
    evaluate_diagnosis,
)
from src.revenue_recovery.safety import (
    ActionAuthorization,
    AuthorizationStatus,
    AuthorizationVerificationError,
    CapacityExceededError,
    CapacityGovernor,
    CircuitBreaker,
    CircuitBrokenError,
    CircuitBreakerState,
    CryptographicAuthorizer,
    GranularCircuitBreakerRegistry,
    KillSwitchActiveError,
    KillSwitchManager,
    KillSwitchScope,
)


# ============================================================================
# Shared Conformance Fixtures
# ============================================================================

@pytest.fixture
def signing_secret() -> str:
    return "conformance_test_secure_signing_secret_998877_abcdef"


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
def authorizer(signing_secret: str) -> CryptographicAuthorizer:
    return CryptographicAuthorizer(signing_secret=signing_secret)


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
    cfg = ExperimentConfig(
        experiment_id="exp_conformance_rct",
        name="Conformance RCT Experiment",
        treatment_ratio=1.0,
        control_ratio=0.0,
        excluded_ratio=0.0,
        salt="conformance_salt_v1",
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
# 18 INVARIANTS CONFORMANCE TEST SUITE
# ============================================================================

class TestArchitecture18InvariantsConformance:
    """Comprehensive, authoritative verification of Invariants INV-01 through INV-18."""

    # ------------------------------------------------------------------------
    # INV-01: AI Recommends; It Does Not Execute
    # ------------------------------------------------------------------------
    def test_inv01_ai_recommendation_only_boundary(self, ai_engine: AIDecisionEngine, case_manager: CaseManager):
        """INV-01: AI engine emits immutable DecisionArtifact and has zero execution capabilities."""
        event = PaymentFailureEvent(
            customer_id="cust_inv01",
            invoice_id="inv_inv01",
            amount_in_cents=5000,
            failure_reason=FailureReason.GENERIC_DECLINE,
            gateway_reference="gw_inv01",
        )
        case = case_manager.create_case(event)
        diag = evaluate_diagnosis(event)
        case = case_manager.transition_case(case.case_id, CaseState.DIAGNOSED)
        case = case_manager.transition_case(case.case_id, CaseState.EVALUATING)

        artifact = ai_engine.evaluate_case(case, diag)
        assert isinstance(artifact, DecisionArtifact)
        assert hasattr(artifact, "recommended_action")
        assert not hasattr(ai_engine, "execute")
        assert not hasattr(ai_engine, "dispatch")
        assert not hasattr(ai_engine, "charge")
        assert not hasattr(ai_engine, "send")
        assert not hasattr(ai_engine, "mint_authorization")

    # ------------------------------------------------------------------------
    # INV-02: Least-Privilege Authority Boundaries
    # ------------------------------------------------------------------------
    def test_inv02_least_privilege_authority_isolation(
        self,
        ai_engine: AIDecisionEngine,
        policy_engine: PolicyEngine,
        scheduler: ComplianceScheduler,
        arbitrator: ControlPlaneArbitrator,
        ledger: RevenueLedger,
        dispute_handler: SettlementDisputeHandler,
        evidence_engine: EvidenceEngine,
    ):
        """INV-02: Strict service separation; no shared god-objects or cross-role authority leaks."""
        prohibited_execution_methods = ["execute", "dispatch", "charge", "send_message"]
        prohibited_minting_methods = ["mint_authorization", "sign_token", "create_authorization"]

        non_execution_services = [
            ai_engine,
            policy_engine,
            scheduler,
            arbitrator,
            ledger,
            dispute_handler,
            evidence_engine,
        ]

        for svc in non_execution_services:
            for m in prohibited_execution_methods:
                assert not hasattr(svc, m), f"{type(svc).__name__} violates INV-02 by exposing execution method '{m}'"
            for m in prohibited_minting_methods:
                assert not hasattr(svc, m), f"{type(svc).__name__} violates INV-02 by exposing token-minting method '{m}'"

    # ------------------------------------------------------------------------
    # INV-03: Capability-Based Action Authorization
    # ------------------------------------------------------------------------
    def test_inv03_capability_based_action_authorization(self, authorizer: CryptographicAuthorizer):
        """INV-03: Cryptographically signed ActionAuthorization with TTL, amount, case, and channel."""
        t0 = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
        auth = authorizer.mint_authorization(
            case_id="case_inv03",
            customer_id="cust_inv03",
            action_type=ActionType.RETRY_CHARGE,
            max_amount_in_cents=10000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="1.0.0",
            decision_id="dec_inv03",
            idempotency_key="idem_inv03",
            expires_at=t0 + timedelta(minutes=15),
            current_time=t0,
        )

        assert auth.status == AuthorizationStatus.ISSUED
        assert len(auth.signature) == 64
        assert auth.max_amount_in_cents == 10000
        assert auth.channel == ActionChannel.DIRECT_PAYMENT_GATEWAY

        # Verification succeeds with valid token
        assert authorizer.verify_authorization(
            token=auth,
            expected_customer_id="cust_inv03",
            requested_amount_in_cents=10000,
            expected_currency="INR",
            expected_channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            current_time=t0 + timedelta(minutes=5),
        ) is True

        # Single-bit signature tampering fails closed
        tampered_sig = ("0" if auth.signature[0] != "0" else "1") + auth.signature[1:]
        tampered_auth = auth.model_copy(update={"signature": tampered_sig})
        with pytest.raises(AuthorizationVerificationError, match="signature mismatch"):
            authorizer.verify_authorization(
                token=tampered_auth,
                expected_customer_id="cust_inv03",
                requested_amount_in_cents=10000,
                expected_currency="INR",
                expected_channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
                current_time=t0 + timedelta(minutes=5),
            )

    # ------------------------------------------------------------------------
    # INV-04: Executor Acts ONLY on Valid Signed Token
    # ------------------------------------------------------------------------
    def test_inv04_executor_acts_only_on_valid_signed_token(
        self, executor: ActionExecutor, authorizer: CryptographicAuthorizer
    ):
        """INV-04: Token signature, expiry, and scope validation before any execution call."""
        t0 = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
        auth = authorizer.mint_authorization(
            case_id="case_inv04",
            customer_id="cust_inv04",
            action_type=ActionType.RETRY_CHARGE,
            max_amount_in_cents=10000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="1.0.0",
            decision_id="dec_inv04",
            idempotency_key="idem_inv04",
            expires_at=t0 + timedelta(minutes=15),
            current_time=t0,
        )

        req = ExecutionRequest(
            case_id="case_inv04",
            customer_id="cust_inv04",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=10000,
            currency="INR",
            destination_url="http://127.0.0.1:8000/charge",
            action_payload={"amount": 10000},
            idempotency_key="idem_inv04",
        )

        # 1. Expired token is rejected
        with pytest.raises(AuthorizationVerificationError, match="expired"):
            executor.execute_action(
                request=req,
                token=auth,
                current_time=t0 + timedelta(minutes=20),
            )

        # 2. Over-limit amount is rejected
        req_over = req.model_copy(update={"amount_in_cents": 15000})
        with pytest.raises(AuthorizationVerificationError, match="exceeds"):
            executor.execute_action(
                request=req_over,
                token=auth,
                current_time=t0 + timedelta(minutes=5),
            )

    # ------------------------------------------------------------------------
    # INV-05: Strict MVP Sandbox Isolation
    # ------------------------------------------------------------------------
    def test_inv05_strict_mvp_sandbox_network_isolation(self, sandbox_guard: SandboxGuard):
        """INV-05: Egress allowlist validation; refusal of non-sandbox URIs & technical network isolation."""
        # Non-sandbox and cloud metadata destinations fail closed
        forbidden_targets = [
            "https://api.stripe.com/v1/charges",
            "https://api.razorpay.com/v1/payments",
            "https://api.twilio.com/2010-04-01/Accounts",
            "http://169.254.169.254/latest/meta-data/",
            "http://93.184.216.34:8000/simulator",
            "http://evil-sandbox.attacker.com",
        ]
        for url in forbidden_targets:
            with pytest.raises(SandboxViolationError):
                sandbox_guard.check_egress_allowed(url)
            assert sandbox_guard.is_url_allowed(url) is False

        # Allowed sandbox simulator passes
        assert sandbox_guard.is_url_allowed("http://127.0.0.1:8000/simulator/charge") is True

    # ------------------------------------------------------------------------
    # INV-06: Zero Production Credentials in MVP
    # ------------------------------------------------------------------------
    def test_inv06_zero_production_credentials_fails_closed(self, monkeypatch):
        """INV-06: Config validator & environment scanner fail startup if production keys/URIs present."""
        reset_cached_settings()
        # Setting production key pattern strictly raises ProductionBoundaryViolationError or ValueError
        with pytest.raises((ValueError, ProductionBoundaryViolationError)):
            AppSettings(
                auth_signing_secret="explicit-secure-sandbox-signing-secret-12345",
                stripe_api_key="sk_live_51ABC123XYZ456DEF789",
            )
        reset_cached_settings()

    # ------------------------------------------------------------------------
    # INV-07: Mandatory Compliance Obligations Cannot Be Discarded
    # ------------------------------------------------------------------------
    def test_inv07_mandatory_compliance_obligations_cannot_be_discarded(
        self, case_manager: CaseManager, scheduler: ComplianceScheduler
    ):
        """INV-07: Deterministic Scheduler prioritizes mandatory disclosures over optional recovery."""
        t0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
        event = PaymentFailureEvent(
            customer_id="cust_inv07",
            invoice_id="inv_inv07",
            amount_in_cents=5000,
            failure_reason=FailureReason.GENERIC_DECLINE,
            gateway_reference="gw_inv07",
        )
        case = case_manager.create_case(event)

        mandatory_ob = ComplianceObligation(
            obligation_id="ob_inv07_mand",
            case_id=case.case_id,
            obligation_type=ObligationType.MANDATORY_DISCLOSURE,
            is_mandatory=True,
            scheduled_time=t0,
        )
        optional_ob = ComplianceObligation(
            obligation_id="ob_inv07_opt",
            case_id=case.case_id,
            obligation_type=ObligationType.RETRY_WINDOW,
            is_mandatory=False,
            scheduled_time=t0,
        )

        plan = scheduler.schedule_case_obligations(
            case=case, obligations=[mandatory_ob, optional_ob], current_time=t0
        )
        assert len(plan.scheduled_obligations) == 1
        assert plan.scheduled_obligations[0].obligation_type == ObligationType.MANDATORY_DISCLOSURE
        assert len(plan.collision_resolutions) == 1
        assert plan.collision_resolutions[0].obligation_type == ObligationType.RETRY_WINDOW

    # ------------------------------------------------------------------------
    # INV-08: Multi-Way Obligation Collision Resolution
    # ------------------------------------------------------------------------
    def test_inv08_multi_way_obligation_collision_resolution(
        self, case_manager: CaseManager, scheduler: ComplianceScheduler
    ):
        """INV-08: Deterministic precedence arbitration with legal safety fallbacks."""
        t0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
        event = PaymentFailureEvent(
            customer_id="cust_inv08",
            invoice_id="inv_inv08",
            amount_in_cents=5000,
            failure_reason=FailureReason.GENERIC_DECLINE,
            gateway_reference="gw_inv08",
        )
        case = case_manager.create_case(event)

        obs = [
            ComplianceObligation(obligation_id="ob_retry", case_id=case.case_id, obligation_type=ObligationType.RETRY_WINDOW, is_mandatory=True, scheduled_time=t0),
            ComplianceObligation(obligation_id="ob_disclosure", case_id=case.case_id, obligation_type=ObligationType.MANDATORY_DISCLOSURE, is_mandatory=True, scheduled_time=t0),
            ComplianceObligation(obligation_id="ob_cooling", case_id=case.case_id, obligation_type=ObligationType.COOLING_OFF, is_mandatory=True, scheduled_time=t0),
            ComplianceObligation(obligation_id="ob_consent", case_id=case.case_id, obligation_type=ObligationType.CONSENT_CHECK, is_mandatory=True, scheduled_time=t0),
        ]

        plan = scheduler.schedule_case_obligations(case=case, obligations=obs, current_time=t0)
        # Dominant: MANDATORY_DISCLOSURE
        assert len(plan.scheduled_obligations) == 1
        assert plan.scheduled_obligations[0].obligation_type == ObligationType.MANDATORY_DISCLOSURE

        # Subordinates: CONSENT_CHECK, COOLING_OFF, RETRY_WINDOW
        assert len(plan.collision_resolutions) == 3
        subordinate_types = [ob.obligation_type for ob in plan.collision_resolutions]
        assert ObligationType.CONSENT_CHECK in subordinate_types
        assert ObligationType.COOLING_OFF in subordinate_types
        assert ObligationType.RETRY_WINDOW in subordinate_types

    # ------------------------------------------------------------------------
    # INV-09: Safety Freezes Cannot Be Bypassed via Retry
    # ------------------------------------------------------------------------
    def test_inv09_safety_freezes_cannot_be_bypassed_via_retry(
        self,
        case_manager: CaseManager,
        ai_engine: AIDecisionEngine,
        arbitrator: ControlPlaneArbitrator,
        experiment_engine: ExperimentEngine,
    ):
        """INV-09: Frozen state in DB & Arbitrator rejects retries on safety trip."""
        event = PaymentFailureEvent(
            customer_id="cust_inv09",
            invoice_id="inv_inv09",
            amount_in_cents=5000,
            failure_reason=FailureReason.GENERIC_DECLINE,
            gateway_reference="gw_inv09",
        )
        case = case_manager.create_case(event)
        diag = evaluate_diagnosis(event)
        case = case_manager.transition_case(case.case_id, CaseState.DIAGNOSED)
        case = case_manager.transition_case(case.case_id, CaseState.EVALUATING)
        dec = ai_engine.evaluate_case(case, diag)

        # Freeze case
        case = case_manager.freeze_case(case.case_id, reason="CRITICAL_ANOMALY")
        assert case.state == CaseState.FROZEN

        # State machine transition fails
        with pytest.raises(InvalidStateTransitionError):
            case_manager.transition_case(case.case_id, CaseState.SCHEDULED)
        with pytest.raises(InvalidStateTransitionError):
            case_manager.transition_case(case.case_id, CaseState.EXECUTING)

        # Arbitrator outcome is BLOCK
        exp = experiment_engine.assign(case)
        arb_res = arbitrator.arbitrate(case=case, diagnosis=diag, decision=dec, experiment_assignment=exp.assignment)
        assert arb_res.arbitrated_outcome == ArbitratedOutcome.BLOCK

    # ------------------------------------------------------------------------
    # INV-10: Incident Obligations Route Through Authoritative Scheduler
    # ------------------------------------------------------------------------
    def test_inv10_incident_obligations_route_through_authoritative_scheduler(
        self, case_manager: CaseManager, scheduler: ComplianceScheduler
    ):
        """INV-10: Common ingestion queue for incident obligations into Scheduler."""
        t0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
        event = PaymentFailureEvent(
            customer_id="cust_inv10",
            invoice_id="inv_inv10",
            amount_in_cents=5000,
            failure_reason=FailureReason.GENERIC_DECLINE,
            gateway_reference="gw_inv10",
        )
        case = case_manager.create_case(event)

        incident_ob = ComplianceObligation(
            case_id=case.case_id,
            obligation_type=ObligationType.COOLING_OFF,
            is_mandatory=True,
            scheduled_time=t0,
            resolution_reason="INCIDENT_MANUAL_HOLD",
        )

        res = scheduler.schedule_obligation(incident_ob, current_time=t0)
        assert res.status == ObligationStatus.PENDING.value
        assert res.resolution_reason == "INCIDENT_MANUAL_HOLD"

    # ------------------------------------------------------------------------
    # INV-11: Gross Recovered != Confirmed Recovered
    # ------------------------------------------------------------------------
    def test_inv11_two_stage_revenue_separation(self, ledger: RevenueLedger):
        """INV-11: Two-stage revenue ledger requiring settlement reconciliation."""
        cid = "case_inv11"
        # Stage 1: Gross recovery requires net_confirmed_amount == 0
        ledger.record_gross_recovery(
            case_id=cid,
            gross_amount=10000,
            currency="INR",
            execution_id="exec_inv11",
        )
        s1 = ledger.get_case_summary(cid)
        assert s1.total_gross_recovered == 10000
        assert s1.total_net_confirmed == 0

        # Stage 2: Settlement records confirmed revenue
        ledger.record_confirmed_settlement(
            case_id=cid,
            gross_amount=10000,
            net_confirmed_amount=9800,
            currency="INR",
            execution_id="exec_inv11",
        )
        s2 = ledger.get_case_summary(cid)
        assert s2.total_gross_recovered == 10000
        assert s2.total_net_confirmed == 9800

    # ------------------------------------------------------------------------
    # INV-12: Dispute & Chargeback Financial Tracking
    # ------------------------------------------------------------------------
    def test_inv12_dispute_and_chargeback_financial_tracking(
        self, ledger: RevenueLedger, dispute_handler: SettlementDisputeHandler
    ):
        """INV-12: Dispute webhooks adjust net confirmed revenue to negative/loss."""
        cid = "case_inv12"
        ledger.record_gross_recovery(cid, 10000, "INR", "exec_inv12")
        ledger.record_confirmed_settlement(cid, 10000, 9800, "INR", "exec_inv12")

        # Inbound Dispute
        hook = DisputeWebhook(
            event_id="evt_inv12_disp",
            dispute_id="dp_inv12",
            case_id=cid,
            execution_id="exec_inv12",
            disputed_amount=10000,
            currency="INR",
            reason=DisputeReason.FRAUDULENT,
            stage=DisputeStage.NEEDS_RESPONSE,
        )
        entry = dispute_handler.process_dispute(hook)
        assert entry.financial_state == FinancialState.DISPUTED
        assert entry.net_confirmed_amount == 0

        summary = ledger.get_case_summary(cid)
        assert summary.latest_state == FinancialState.DISPUTED

    # ------------------------------------------------------------------------
    # INV-13: Backtesting Never Presented as Causal Lift
    # ------------------------------------------------------------------------
    def test_inv13_backtesting_never_presented_as_causal_lift(
        self, ledger: RevenueLedger, audit_logger: CryptographicAuditLogger
    ):
        """INV-13: Evidence Engine requires randomized controlled experiment logs."""
        engine = EvidenceEngine(ledger=ledger, audit_logger=audit_logger)
        # Evaluation with is_backtest=True is strictly blocked
        entry = engine.evaluate_window(
            metric_id="lift_backtest",
            evaluation_window="2026-Q3",
            treatment_case_ids=["t1", "t2"],
            control_case_ids=["c1", "c2"],
            is_backtest=True,
        )
        assert entry.incremental_lift is None
        assert entry.reporting_state == ReportingState.NOT_REPORTABLE
        assert BlockingReason.BACKTESTING_ONLY.value in entry.blocking_reasons

        # Missing control cohort is strictly blocked from causal lift
        entry_no_ctrl = engine.evaluate_window(
            metric_id="lift_no_ctrl",
            evaluation_window="2026-Q3",
            treatment_case_ids=["t1", "t2"],
            control_case_ids=[],
            is_backtest=False,
        )
        assert entry_no_ctrl.incremental_lift is None
        assert entry_no_ctrl.reporting_state == ReportingState.DIRECTIONAL
        assert BlockingReason.NO_EXPERIMENT_CONTROL.value in entry_no_ctrl.blocking_reasons

    # ------------------------------------------------------------------------
    # INV-14: Headline Metrics Cannot Silently Disappear
    # ------------------------------------------------------------------------
    def test_inv14_headline_metrics_cannot_silently_disappear(
        self, ledger: RevenueLedger, audit_logger: CryptographicAuditLogger
    ):
        """INV-14: Evidence Registry enforces required reporting states & blocking reason codes."""
        engine = EvidenceEngine(ledger=ledger, audit_logger=audit_logger)
        for state in ReportingState:
            assert isinstance(state.value, str)
        for reason in BlockingReason:
            assert isinstance(reason.value, str)

        entry = engine.evaluate_window(
            metric_id="headline_metric_01",
            evaluation_window="2026-Q3",
            treatment_case_ids=["t1"],
            control_case_ids=["c1"],
            min_sample_size=10,
        )
        assert entry.reporting_state == ReportingState.DATA_PENDING
        assert BlockingReason.INSUFFICIENT_SAMPLE_SIZE.value in entry.blocking_reasons

        # Metric persists in registry
        retrieved = engine.get_evidence("headline_metric_01", "2026-Q3")
        assert retrieved is not None
        assert retrieved.metric_id == "headline_metric_01"

    # ------------------------------------------------------------------------
    # INV-15: Kill Switch & Circuit Breaker Fail-Closed
    # ------------------------------------------------------------------------
    def test_inv15_kill_switch_and_circuit_breaker_fail_closed(
        self,
        kill_switch: KillSwitchManager,
        circuit_breakers: GranularCircuitBreakerRegistry,
        capacity_governor: CapacityGovernor,
    ):
        """INV-15: Global & granular kill switch and circuit breakers halt execution immediately."""
        # 1. Global Kill Switch
        kill_switch.activate_global(reason="SAFETY_EMERGENCY")
        assert kill_switch.is_global_active() is True
        assert kill_switch.is_active() is True

        # 2. Granular Kill Switch
        kill_switch.deactivate_global()
        kill_switch.activate_action_type(ActionType.RETRY_CHARGE, reason="RETRY_PAUSED")
        assert kill_switch.is_active(action_type=ActionType.RETRY_CHARGE) is True
        assert kill_switch.is_active(action_type=ActionType.OFFER_PAYMENT_PLAN) is False

        # 3. Circuit Breaker
        cb = circuit_breakers.get_or_create("SMS", failure_threshold=2)
        assert cb.state == CircuitBreakerState.CLOSED
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitBreakerState.OPEN
        with pytest.raises(CircuitBrokenError):
            cb.check_execution_allowed()

        # 4. Capacity Governor
        with pytest.raises(CapacityExceededError):
            capacity_governor.check_capacity_available(requested_amount_in_cents=10000000)

    # ------------------------------------------------------------------------
    # INV-16: Idempotency Across Execution & Retry
    # ------------------------------------------------------------------------
    def test_inv16_idempotency_across_execution_and_retry(
        self, executor: ActionExecutor, authorizer: CryptographicAuthorizer
    ):
        """INV-16: Enforced unique idempotency keys on authorizations & executions."""
        t0 = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
        auth = authorizer.mint_authorization(
            case_id="case_inv16",
            customer_id="cust_inv16",
            action_type=ActionType.RETRY_CHARGE,
            max_amount_in_cents=10000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="1.0.0",
            decision_id="dec_inv16",
            idempotency_key="idem_key_inv16",
            expires_at=t0 + timedelta(minutes=15),
            current_time=t0,
        )

        req1 = ExecutionRequest(
            case_id="case_inv16",
            customer_id="cust_inv16",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=10000,
            currency="INR",
            destination_url="http://127.0.0.1:8000/charge",
            action_payload={"amount": 10000},
            idempotency_key=auth.idempotency_key,
        )
        r1 = executor.execute_action(request=req1, token=auth, current_time=t0)
        r2 = executor.execute_action(request=req1, token=auth, current_time=t0)

        assert r1.idempotency_key == r2.idempotency_key
        assert r1.status == ExecutionStatus.SUCCESS
        assert r2.status == ExecutionStatus.SUCCESS

        # Conflicting payload with same idempotency key fails closed
        req_conflict = req1.model_copy(update={"amount_in_cents": 5000})
        auth_conflict = authorizer.mint_authorization(
            case_id="case_inv16",
            customer_id="cust_inv16",
            action_type=ActionType.RETRY_CHARGE,
            max_amount_in_cents=10000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="1.0.0",
            decision_id="dec_inv16",
            idempotency_key="idem_key_inv16",
            expires_at=t0 + timedelta(minutes=15),
            current_time=t0,
        )
        with pytest.raises(IdempotencyConflictError, match="Conflicting re-execution rejected"):
            executor.execute_action(request=req_conflict, token=auth_conflict, current_time=t0)

    # ------------------------------------------------------------------------
    # INV-17: Immutable Decision Artifacts with Input Snapshot Hashes
    # ------------------------------------------------------------------------
    def test_inv17_decision_artifacts_input_snapshot_hashes(self, ai_engine: AIDecisionEngine, case_manager: CaseManager):
        """INV-17: SHA-256 canonical hashing of model inputs & immutable storage."""
        event = PaymentFailureEvent(
            customer_id="cust_inv17",
            invoice_id="inv_inv17",
            amount_in_cents=5000,
            failure_reason=FailureReason.GENERIC_DECLINE,
            gateway_reference="gw_inv17",
        )
        case = case_manager.create_case(event)
        diag = evaluate_diagnosis(event)
        case = case_manager.transition_case(case.case_id, CaseState.DIAGNOSED)
        case = case_manager.transition_case(case.case_id, CaseState.EVALUATING)

        artifact = ai_engine.evaluate_case(case, diag)

        # Hash stability and determinism
        d1 = {"b": 2, "a": 1, "nested": {"y": [1, 2], "x": "val"}}
        d2 = {"nested": {"x": "val", "y": [1, 2]}, "a": 1, "b": 2}
        assert compute_canonical_input_hash(d1) == compute_canonical_input_hash(d2)

        # Deep immutability verification
        with pytest.raises(Exception):
            artifact.confidence_score = 0.99
        with pytest.raises(Exception):
            artifact.input_snapshot["tampered"] = True

    # ------------------------------------------------------------------------
    # INV-18: Complete Cryptographic Audit Logging
    # ------------------------------------------------------------------------
    def test_inv18_complete_cryptographic_audit_trail(self, audit_logger: CryptographicAuditLogger):
        """INV-18: Append-only audit logger for every state change & decision."""
        t0 = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
        e1 = audit_logger.append(event_type="CASE_CREATED", payload={"case_id": "c1"}, timestamp=t0)
        e2 = audit_logger.append(event_type="DIAGNOSED", payload={"case_id": "c1", "risk": "LOW"}, timestamp=t0)
        e3 = audit_logger.append(event_type="ARBITRATED", payload={"case_id": "c1", "outcome": "PROCEED"}, timestamp=t0)

        assert e1.sequence_number == 0
        assert e2.sequence_number == 1
        assert e3.sequence_number == 2
        assert e2.previous_hash == e1.entry_hash
        assert e3.previous_hash == e2.entry_hash
        assert audit_logger.verify_chain_integrity() is True
