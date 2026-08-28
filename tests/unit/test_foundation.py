"""Consolidated foundation layer integration tests (TICKET-04).

Architecture Baseline: Frozen Architecture Baseline v11.
Proves interoperability between AppSettings safeguards, core domain models,
domain event envelopes, and the append-only cryptographic audit logger.
"""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from src.revenue_recovery.foundation import (
    GENESIS_PREVIOUS_HASH,
    ActionChannel,
    ActionType,
    AppSettings,
    AuditEntry,
    AuditIntegrityError,
    CaseState,
    ComplianceObligation,
    CryptographicAuditLogger,
    DomainEventEnvelope,
    ExecutionStatus,
    FailureReason,
    ImmutableDict,
    ObligationType,
    PaymentFailureEvent,
    RecoveryCase,
    RiskTier,
    canonical_json,
    compute_entry_hash,
    freeze_payload,
    get_settings,
    reset_cached_settings,
)


class TestFoundationIntegration:
    """Integration test suite exercising end-to-end foundation contract flows."""

    def setup_method(self):
        reset_cached_settings()

    def teardown_method(self):
        reset_cached_settings()

    def test_config_settings_and_domain_event_envelope_integration(self):
        """Proves AppSettings properly coordinates with DomainEventEnvelope in sandbox."""
        settings = get_settings()
        assert settings.environment == "sandbox"

        # Create a domain event envelope with settings metadata
        payload = {
            "environment": settings.environment,
            "simulator_payment_url": str(settings.sandbox_payment_simulator_url),
            "simulator_messaging_url": str(settings.sandbox_messaging_simulator_url),
            "customer_id": "cust_12345",
            "status": "INITIALIZED"
        }
        envelope = DomainEventEnvelope[dict](
            event_type="SandboxSystemInitialized",
            idempotency_key="idemp_init_001",
            correlation_id="corr_init_001",
            causation_id="caus_init_001",
            payload=payload
        )
        assert envelope.event_type == "SandboxSystemInitialized"
        assert envelope.payload["environment"] == "sandbox"
        assert envelope.payload["simulator_payment_url"] == str(settings.sandbox_payment_simulator_url)

    def test_payment_failure_event_audit_logging_and_chain_verification(self):
        """Proves PaymentFailureEvent data can be audited and cryptographically chained."""
        logger = CryptographicAuditLogger()
        failure_event = PaymentFailureEvent(
            customer_id="cust_abc",
            invoice_id="inv_xyz",
            amount_in_cents=12500,
            currency="INR",
            failure_reason=FailureReason.INSUFFICIENT_FUNDS,
            failure_code="insufficient_funds",
            gateway_reference="gw_ref_001"
        )

        # Log the failure event
        audit_entry = logger.append(
            event_type="PaymentFailureTriggered",
            payload=failure_event.model_dump()
        )

        assert audit_entry.sequence_number == 0
        assert audit_entry.previous_hash == GENESIS_PREVIOUS_HASH
        assert audit_entry.payload["customer_id"] == "cust_abc"
        assert audit_entry.payload["amount_in_cents"] == 12500
        assert audit_entry.payload["currency"] == "INR"
        assert audit_entry.payload["failure_reason"] == "INSUFFICIENT_FUNDS"

        # Verify cryptographic chain
        assert logger.verify_chain_integrity() is True

    def test_recovery_case_lifecycle_audit_stream(self):
        """Proves a recovery case state progression creates an unbroken audit chain."""
        logger = CryptographicAuditLogger()

        # Step 1: Case creation
        case = RecoveryCase(
            customer_id="cust_999",
            trigger_event_id="evt_trigger_1",
            amount_in_cents=50000,
            currency="INR"
        )
        logger.append("RecoveryCaseCreated", case.model_dump())

        # Step 2: Diagnosis event
        diagnosis_payload = {
            "case_id": case.case_id,
            "previous_state": case.state,
            "new_state": CaseState.DIAGNOSED.value,
            "risk_tier": RiskTier.MEDIUM.value,
            "recommended_strategy": ActionType.RETRY_CHARGE.value
        }
        logger.append("RecoveryCaseDiagnosed", diagnosis_payload)

        # Step 3: Evaluation event
        eval_payload = {
            "case_id": case.case_id,
            "previous_state": CaseState.DIAGNOSED.value,
            "new_state": CaseState.EVALUATING.value,
            "channel": ActionChannel.DIRECT_PAYMENT_GATEWAY.value
        }
        logger.append("RecoveryCaseEvaluating", eval_payload)

        assert len(logger) == 3
        assert logger.entries[0].sequence_number == 0
        assert logger.entries[1].sequence_number == 1
        assert logger.entries[2].sequence_number == 2

        # Verify hash chaining across entries
        assert logger.entries[1].previous_hash == logger.entries[0].entry_hash
        assert logger.entries[2].previous_hash == logger.entries[1].entry_hash
        assert logger.verify_chain_integrity() is True

    def test_compliance_obligation_audit_logging(self):
        """Proves ComplianceObligation models integrate cleanly into audit logging."""
        logger = CryptographicAuditLogger()
        scheduled_time = datetime(2026, 6, 1, 10, 0, 0, tzinfo=timezone.utc)

        obligation = ComplianceObligation(
            case_id="case_obl_001",
            obligation_type=ObligationType.MANDATORY_DISCLOSURE,
            is_mandatory=True,
            scheduled_time=scheduled_time
        )
        entry = logger.append("ComplianceObligationScheduled", obligation.model_dump())

        assert entry.event_type == "ComplianceObligationScheduled"
        assert entry.payload["case_id"] == "case_obl_001"
        assert entry.payload["obligation_type"] == "MANDATORY_DISCLOSURE"
        assert entry.payload["is_mandatory"] is True
        assert logger.verify_chain_integrity() is True

    def test_mixed_domain_event_stream_tamper_detection(self):
        """Proves tampering with any domain event payload in a mixed stream fails closed."""
        logger = CryptographicAuditLogger()

        # Append multiple heterogeneous domain events
        logger.append("ConfigLoaded", {"environment": "sandbox", "version": "1.0.0"})
        logger.append("PaymentFailed", {"customer_id": "c1", "amount_in_cents": 1000})
        logger.append("CaseOpened", {"case_id": "case_1", "state": "OPEN"})
        logger.append("ObligationCreated", {"obligation_type": "COOLING_OFF", "mandatory": True})

        assert len(logger) == 4
        assert logger.verify_chain_integrity() is True

        # Tamper with the 2nd entry (sequence 1)
        tampered_entry = AuditEntry(
            entry_id=logger[1].entry_id,
            sequence_number=1,
            timestamp=logger[1].timestamp,
            event_type="PaymentFailed",
            payload={"customer_id": "c1", "amount_in_cents": 9999999},  # Tampered amount
            previous_hash=logger[1].previous_hash,
            entry_hash=logger[1].entry_hash  # Mismatch
        )
        logger._inject_corrupted_entry_for_test(1, tampered_entry)

        with pytest.raises(AuditIntegrityError, match="Audit payload tampering detected"):
            logger.verify_chain_integrity()

    def test_foundation_module_all_public_symbols_export_integrity(self):
        """Proves every public symbol from Milestone 1 is accessible from the foundation root."""
        import src.revenue_recovery.foundation as foundation

        expected_symbols = [
            "AppSettings",
            "ConfigurationError",
            "ProductionBoundaryViolationError",
            "generate_ephemeral_sandbox_signing_secret",
            "get_settings",
            "load_settings_from_env",
            "reset_cached_settings",
            "scan_environment_for_forbidden_production_artifacts",
            "CaseState",
            "RiskTier",
            "FailureReason",
            "ActionType",
            "ActionChannel",
            "ObligationType",
            "ExecutionStatus",
            "ImmutableBaseModel",
            "PaymentFailureEvent",
            "RecoveryCase",
            "ComplianceObligation",
            "DomainEventEnvelope",
            "GENESIS_PREVIOUS_HASH",
            "AuditEntry",
            "AuditIntegrityError",
            "CryptographicAuditLogger",
            "ImmutableDict",
            "canonical_json",
            "compute_entry_hash",
            "freeze_payload",
        ]

        for sym in expected_symbols:
            assert hasattr(foundation, sym), f"Expected symbol '{sym}' missing from foundation root"
            assert sym in foundation.__all__, f"Symbol '{sym}' missing from foundation.__all__"
