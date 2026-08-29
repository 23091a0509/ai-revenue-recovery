"""Milestone 2 consolidated unit and security tests (TICKET-08).

Architecture Baseline: Frozen Architecture Baseline v11.
Proves end-to-end Execution Safety subsystem integration across CryptographicAuthorizer,
KillSwitchManager, CircuitBreaker, and CapacityGovernor under normal and adversarial conditions.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import pytest

from src.revenue_recovery.foundation.events import (
    ActionChannel,
    ActionType,
)
from src.revenue_recovery.safety import (
    ActionAuthorization,
    AuthorizationStatus,
    AuthorizationVerificationError,
    CapacityExceededError,
    CapacityGovernor,
    CircuitBreaker,
    CircuitBreakerState,
    CircuitBrokenError,
    CryptographicAuthorizer,
    GranularCircuitBreakerRegistry,
    KillSwitchActiveError,
    KillSwitchManager,
    KillSwitchRecord,
    KillSwitchScope,
    SafetyVerdict,
    canonical_signing_string,
    validate_authorizer_signing_secret,
)


class TestMilestone2SafetyIntegrationPipeline:
    """
    Tests the multi-layer execution safety pipeline in strict sequence:
    1. Cryptographic Token Verification
    2. Kill Switch Gate
    3. Circuit Breaker Gate
    4. Capacity Governor Gate
    """

    @pytest.fixture
    def secret(self) -> str:
        return "secure-sandbox-safety-key-12345678"

    @pytest.fixture
    def authorizer(self, secret: str) -> CryptographicAuthorizer:
        return CryptographicAuthorizer(signing_secret=secret)

    @pytest.fixture
    def kill_switch(self) -> KillSwitchManager:
        return KillSwitchManager()

    @pytest.fixture
    def circuit_breakers(self) -> GranularCircuitBreakerRegistry:
        return GranularCircuitBreakerRegistry(default_failure_threshold=2, default_recovery_timeout_seconds=10.0)

    @pytest.fixture
    def capacity_governor(self) -> CapacityGovernor:
        return CapacityGovernor(max_actions_per_window=10, max_volume_in_cents_per_window=100000, window_seconds=60.0)

    def _execute_safety_gate(
        self,
        token: ActionAuthorization,
        authorizer: CryptographicAuthorizer,
        kill_switch: KillSwitchManager,
        circuit_breakers: GranularCircuitBreakerRegistry,
        capacity_governor: CapacityGovernor,
        requested_amount: int,
        channel: ActionChannel,
        current_time: datetime | None = None
    ) -> SafetyVerdict:
        """
        Simulates the authoritative safety evaluation pipeline.
        Returns SafetyVerdict.PASS only if all 4 gates permit execution.
        """
        now = current_time or datetime.now(timezone.utc)

        # Gate 1: Cryptographic Token Verification
        authorizer.verify_authorization(
            token=token,
            expected_customer_id=token.customer_id,
            expected_currency=token.currency,
            requested_amount_in_cents=requested_amount,
            expected_channel=channel,
            current_time=now
        )

        # Gate 2: Kill Switch Evaluation
        kill_switch.check_execution_allowed(
            action_type=token.action_type,
            channel=channel,
            customer_id=token.customer_id,
            case_id=token.case_id
        )

        # Gate 3: Circuit Breaker Evaluation (atomic admission)
        circuit_breakers.check_execution_allowed(target=channel, current_time=now)

        # Gate 4: Capacity Governor Evaluation (atomic reservation)
        capacity_governor.record_action(amount_in_cents=requested_amount, current_time=now)

        return SafetyVerdict.PASS

    def test_all_gates_pass_under_healthy_conditions(
        self,
        authorizer: CryptographicAuthorizer,
        kill_switch: KillSwitchManager,
        circuit_breakers: GranularCircuitBreakerRegistry,
        capacity_governor: CapacityGovernor
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = authorizer.mint_authorization(
            case_id="case_100",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_100",
            max_amount_in_cents=5000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_100",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_100",
            current_time=t0
        )

        verdict = self._execute_safety_gate(
            token=token,
            authorizer=authorizer,
            kill_switch=kill_switch,
            circuit_breakers=circuit_breakers,
            capacity_governor=capacity_governor,
            requested_amount=5000,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            current_time=t0
        )
        assert verdict == SafetyVerdict.PASS

        # Capacity was reserved
        count, vol = capacity_governor.get_current_utilization(current_time=t0)
        assert count == 1
        assert vol == 5000

    def test_tampered_token_fails_closed_before_touching_downstream_gates(
        self,
        authorizer: CryptographicAuthorizer,
        kill_switch: KillSwitchManager,
        circuit_breakers: GranularCircuitBreakerRegistry,
        capacity_governor: CapacityGovernor
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = authorizer.mint_authorization(
            case_id="case_100",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_100",
            max_amount_in_cents=5000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_100",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_100",
            current_time=t0
        )

        # Attacker tampers with signature
        tampered_token = token.model_copy(update={"signature": "bad0000000000000000000000000000000000000000000000000000000000000"})

        with pytest.raises(AuthorizationVerificationError, match="Cryptographic signature mismatch"):
            self._execute_safety_gate(
                token=tampered_token,
                authorizer=authorizer,
                kill_switch=kill_switch,
                circuit_breakers=circuit_breakers,
                capacity_governor=capacity_governor,
                requested_amount=5000,
                channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
                current_time=t0
            )

        # Capacity was NOT reserved
        count, vol = capacity_governor.get_current_utilization(current_time=t0)
        assert count == 0
        assert vol == 0

    def test_kill_switch_fails_closed_before_circuit_breaker_and_capacity(
        self,
        authorizer: CryptographicAuthorizer,
        kill_switch: KillSwitchManager,
        circuit_breakers: GranularCircuitBreakerRegistry,
        capacity_governor: CapacityGovernor
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = authorizer.mint_authorization(
            case_id="case_200",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_200",
            max_amount_in_cents=8000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_200",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_200",
            current_time=t0
        )

        # Activate customer-specific kill switch
        kill_switch.activate_customer("cust_200", reason="Legal freeze", activated_by="compliance_officer")

        with pytest.raises(KillSwitchActiveError, match="Execution halted by CUSTOMER kill switch"):
            self._execute_safety_gate(
                token=token,
                authorizer=authorizer,
                kill_switch=kill_switch,
                circuit_breakers=circuit_breakers,
                capacity_governor=capacity_governor,
                requested_amount=8000,
                channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
                current_time=t0
            )

        # Downstream capacity remains untouched
        count, vol = capacity_governor.get_current_utilization(current_time=t0)
        assert count == 0
        assert vol == 0

    def test_circuit_breaker_fails_closed_before_capacity_consumption(
        self,
        authorizer: CryptographicAuthorizer,
        kill_switch: KillSwitchManager,
        circuit_breakers: GranularCircuitBreakerRegistry,
        capacity_governor: CapacityGovernor
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = authorizer.mint_authorization(
            case_id="case_300",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_300",
            max_amount_in_cents=3000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_300",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_300",
            current_time=t0
        )

        # Trip DIRECT_PAYMENT_GATEWAY circuit breaker
        circuit_breakers.record_failure(ActionChannel.DIRECT_PAYMENT_GATEWAY, current_time=t0)
        circuit_breakers.record_failure(ActionChannel.DIRECT_PAYMENT_GATEWAY, current_time=t0)

        with pytest.raises(CircuitBrokenError, match="is OPEN and blocking execution"):
            self._execute_safety_gate(
                token=token,
                authorizer=authorizer,
                kill_switch=kill_switch,
                circuit_breakers=circuit_breakers,
                capacity_governor=capacity_governor,
                requested_amount=3000,
                channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
                current_time=t0
            )

        # Capacity was NOT consumed
        count, vol = capacity_governor.get_current_utilization(current_time=t0)
        assert count == 0
        assert vol == 0

    def test_capacity_governor_fails_closed_when_volume_ceiling_reached(
        self,
        authorizer: CryptographicAuthorizer,
        kill_switch: KillSwitchManager,
        circuit_breakers: GranularCircuitBreakerRegistry,
        capacity_governor: CapacityGovernor
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        # Governor limit is 100,000 cents
        token = authorizer.mint_authorization(
            case_id="case_400",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_400",
            max_amount_in_cents=150000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_400",
            expires_at=t0 + timedelta(minutes=5),
            idempotency_key="idemp_400",
            current_time=t0
        )

        with pytest.raises(CapacityExceededError, match="Monetary volume limit exceeded"):
            self._execute_safety_gate(
                token=token,
                authorizer=authorizer,
                kill_switch=kill_switch,
                circuit_breakers=circuit_breakers,
                capacity_governor=capacity_governor,
                requested_amount=150000,
                channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
                current_time=t0
            )

        # Utilization remains 0 because request was rejected atomically
        count, vol = capacity_governor.get_current_utilization(current_time=t0)
        assert count == 0
        assert vol == 0


class TestAdversarialTokenTamperingAndForgery:
    """Adversarial security test cases exploring all token tampering and forgery vectors."""

    @pytest.fixture
    def authorizer(self) -> CryptographicAuthorizer:
        return CryptographicAuthorizer(signing_secret="super-secure-key-123456789012")

    @pytest.fixture
    def valid_token(self, authorizer: CryptographicAuthorizer) -> ActionAuthorization:
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        return authorizer.mint_authorization(
            case_id="case_legit_1",
            action_type=ActionType.RETRY_CHARGE,
            customer_id="cust_legit_1",
            max_amount_in_cents=50000,
            currency="INR",
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            policy_version="v1.0",
            decision_id="dec_legit_1",
            expires_at=t0 + timedelta(minutes=10),
            idempotency_key="idemp_legit_1",
            current_time=t0
        )

    @pytest.mark.parametrize("tampered_field,bad_value", [
        ("case_id", "case_evil_hacked"),
        ("customer_id", "cust_victim_account"),
        ("action_type", ActionType.OFFER_PAYMENT_PLAN),
        ("max_amount_in_cents", 9999999),
        ("currency", "USD"),
        ("channel", ActionChannel.SMS),
        ("policy_version", "v999.0_bypass"),
        ("decision_id", "dec_forged_999"),
        ("idempotency_key", "idemp_tampered_key_12345"),
    ])
    def test_single_field_tampering_fails_verification(
        self,
        authorizer: CryptographicAuthorizer,
        valid_token: ActionAuthorization,
        tampered_field: str,
        bad_value: str | int | ActionType | ActionChannel
    ):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        tampered = valid_token.model_copy(update={tampered_field: bad_value})

        with pytest.raises(AuthorizationVerificationError):
            authorizer.verify_authorization(
                token=tampered,
                expected_customer_id=tampered.customer_id,
                expected_currency=tampered.currency,
                requested_amount_in_cents=1000,
                expected_channel=tampered.channel,
                current_time=t0
            )

    def test_signature_byte_inversion_rejected(self, authorizer: CryptographicAuthorizer, valid_token: ActionAuthorization):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        sig = valid_token.signature
        # Invert last character
        bad_char = "0" if sig[-1] != "0" else "1"
        corrupted_sig = sig[:-1] + bad_char
        corrupted = valid_token.model_copy(update={"signature": corrupted_sig})

        with pytest.raises(AuthorizationVerificationError, match="Cryptographic signature mismatch"):
            authorizer.verify_authorization(
                token=corrupted,
                expected_customer_id=valid_token.customer_id,
                expected_currency=valid_token.currency,
                requested_amount_in_cents=1000,
                expected_channel=valid_token.channel,
                current_time=t0
            )

    def test_replay_after_expiration_rejected(self, authorizer: CryptographicAuthorizer, valid_token: ActionAuthorization):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        t_expired = t0 + timedelta(minutes=10, seconds=1)

        with pytest.raises(AuthorizationVerificationError, match="Token has expired"):
            authorizer.verify_authorization(
                token=valid_token,
                expected_customer_id=valid_token.customer_id,
                expected_currency=valid_token.currency,
                requested_amount_in_cents=1000,
                expected_channel=valid_token.channel,
                current_time=t_expired
            )


class TestSafetyPackageExportsIntegrity:
    """Verifies that the entire safety layer exports complete and consistent public API symbols."""

    def test_all_safety_public_exports_present(self):
        import src.revenue_recovery.safety as safety
        expected_exports = [
            "ActionAuthorization",
            "AuthorizationStatus",
            "AuthorizationVerificationError",
            "CryptographicAuthorizer",
            "canonical_signing_string",
            "validate_authorizer_signing_secret",
            "KillSwitchActiveError",
            "KillSwitchManager",
            "KillSwitchRecord",
            "KillSwitchScope",
            "CircuitBreakerState",
            "SafetyVerdict",
            "CircuitBrokenError",
            "CapacityExceededError",
            "CircuitBreaker",
            "GranularCircuitBreakerRegistry",
            "CapacityGovernor",
        ]
        for exp in expected_exports:
            assert hasattr(safety, exp), f"Symbol '{exp}' missing from src.revenue_recovery.safety"
            assert exp in safety.__all__, f"Symbol '{exp}' not listed in safety.__all__"
