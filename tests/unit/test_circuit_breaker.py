"""Unit and concurrency tests for fail-closed Circuit Breaker and Capacity Governor (TICKET-07).

Architecture Baseline: Frozen Architecture Baseline v11.
Proves 3-state state machine transitions, atomic HALF_OPEN probe admission via check_execution_allowed(),
read-only inspection via can_attempt_probe(), and thread-safe atomic capacity reservation.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import pytest

from src.revenue_recovery.foundation.events import ActionChannel
from src.revenue_recovery.safety import (
    CapacityExceededError,
    CapacityGovernor,
    CircuitBreaker,
    CircuitBreakerState,
    CircuitBrokenError,
    GranularCircuitBreakerRegistry,
    SafetyVerdict,
)


class TestCircuitBreaker:
    """Tests for CircuitBreaker 3-state state machine and fail-closed checks."""

    def test_initial_state_is_closed(self):
        cb = CircuitBreaker(target="gateway_test", failure_threshold=3, recovery_timeout_seconds=10.0)
        assert cb.state == CircuitBreakerState.CLOSED
        assert cb.can_attempt_probe() is True
        assert cb.check_execution_allowed() is True
        assert cb.acquire_execution_permission() is True

    def test_failures_reach_threshold_trips_to_open(self):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        cb = CircuitBreaker(target="gateway_test", failure_threshold=3, recovery_timeout_seconds=10.0)

        cb.record_failure(current_time=t0)
        assert cb.get_state(current_time=t0) == CircuitBreakerState.CLOSED

        cb.record_failure(current_time=t0)
        assert cb.get_state(current_time=t0) == CircuitBreakerState.CLOSED

        # 3rd failure trips to OPEN
        cb.record_failure(current_time=t0)
        assert cb.get_state(current_time=t0) == CircuitBreakerState.OPEN
        assert cb.can_attempt_probe(current_time=t0) is False

        # OPEN state fails closed
        with pytest.raises(CircuitBrokenError) as exc_info:
            cb.check_execution_allowed(current_time=t0)
        assert exc_info.value.target == "gateway_test"
        assert exc_info.value.state == CircuitBreakerState.OPEN

        with pytest.raises(CircuitBrokenError):
            cb.acquire_execution_permission(current_time=t0)

    def test_success_resets_consecutive_failures(self):
        cb = CircuitBreaker(target="gateway_test", failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        assert cb._consecutive_failures == 2

        cb.record_success()
        assert cb._consecutive_failures == 0
        assert cb.state == CircuitBreakerState.CLOSED

    def test_transition_from_open_to_half_open_after_timeout(self):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        cb = CircuitBreaker(target="gateway_test", failure_threshold=2, recovery_timeout_seconds=10.0)

        cb.record_failure(current_time=t0)
        cb.record_failure(current_time=t0)
        assert cb.get_state(current_time=t0) == CircuitBreakerState.OPEN

        # Before timeout (9 seconds later), still OPEN
        t_before = t0 + timedelta(seconds=9)
        with pytest.raises(CircuitBrokenError):
            cb.check_execution_allowed(current_time=t_before)
        assert cb.get_state(current_time=t_before) == CircuitBreakerState.OPEN
        assert cb.can_attempt_probe(current_time=t_before) is False

        # After timeout (10 seconds later), transitions to HALF_OPEN
        t_after = t0 + timedelta(seconds=10)
        assert cb.can_attempt_probe(current_time=t_after) is True
        assert cb.get_state(current_time=t_after) == CircuitBreakerState.HALF_OPEN

    def test_half_open_success_resets_to_closed(self):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        cb = CircuitBreaker(target="gateway_test", failure_threshold=2, recovery_timeout_seconds=10.0, half_open_success_threshold=2, half_open_max_probes=2)

        cb.record_failure(current_time=t0)
        cb.record_failure(current_time=t0)

        t_recovery = t0 + timedelta(seconds=11)
        assert cb.check_execution_allowed(current_time=t_recovery) is True

        # First trial success in HALF_OPEN
        cb.record_success(current_time=t_recovery)
        assert cb.get_state(current_time=t_recovery) == CircuitBreakerState.HALF_OPEN

        # Second trial success restores CLOSED
        assert cb.check_execution_allowed(current_time=t_recovery) is True
        cb.record_success(current_time=t_recovery)
        assert cb.get_state(current_time=t_recovery) == CircuitBreakerState.CLOSED
        assert cb.check_execution_allowed() is True

    def test_half_open_failure_immediately_trips_to_open(self):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        cb = CircuitBreaker(target="gateway_test", failure_threshold=2, recovery_timeout_seconds=10.0)

        cb.record_failure(current_time=t0)
        cb.record_failure(current_time=t0)

        t_recovery = t0 + timedelta(seconds=11)
        assert cb.check_execution_allowed(current_time=t_recovery) is True
        assert cb.get_state(current_time=t_recovery) == CircuitBreakerState.HALF_OPEN

        # Trial failure immediately trips back to OPEN
        cb.record_failure(current_time=t_recovery)
        assert cb.get_state(current_time=t_recovery) == CircuitBreakerState.OPEN
        with pytest.raises(CircuitBrokenError):
            cb.check_execution_allowed(current_time=t_recovery)

    def test_manual_trip_and_reset(self):
        cb = CircuitBreaker(target="manual_test")
        cb.trip_manually()
        assert cb.state == CircuitBreakerState.OPEN
        with pytest.raises(CircuitBrokenError):
            cb.check_execution_allowed()

        cb.reset()
        assert cb.state == CircuitBreakerState.CLOSED
        assert cb.check_execution_allowed() is True


class TestHalfOpenConcurrencyAndProbeControl:
    """Deterministic concurrency tests proving check_execution_allowed() atomically limits HALF_OPEN probes."""

    def test_check_execution_allowed_atomically_limits_concurrent_probes(self):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        cb = CircuitBreaker(
            target="concurrent_probe_test",
            failure_threshold=1,
            recovery_timeout_seconds=10.0,
            half_open_success_threshold=1,
            half_open_max_probes=1
        )
        cb.record_failure(current_time=t0)
        t_recovery = t0 + timedelta(seconds=11)

        # Confirm breaker is in HALF_OPEN
        assert cb.get_state(current_time=t_recovery) == CircuitBreakerState.HALF_OPEN

        admitted = []
        rejected = []

        def probe_attempt(caller_id: int):
            try:
                cb.check_execution_allowed(current_time=t_recovery)
                admitted.append(caller_id)
            except CircuitBrokenError:
                rejected.append(caller_id)

        # 20 concurrent threads attempt check_execution_allowed() during HALF_OPEN
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(probe_attempt, i) for i in range(20)]
            for f in futures:
                f.result()

        # Exactly 1 probe was admitted; 19 were rejected/failed closed
        assert len(admitted) == 1
        assert len(rejected) == 19

        # When the admitted probe succeeds, state transitions to CLOSED
        cb.record_success(current_time=t_recovery)
        assert cb.get_state(current_time=t_recovery) == CircuitBreakerState.CLOSED

        # Now all subsequent requests can pass check_execution_allowed normally
        assert cb.check_execution_allowed(current_time=t_recovery) is True

    def test_half_open_probe_failure_trips_to_open_and_blocks_all(self):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        cb = CircuitBreaker(
            target="probe_failure_test",
            failure_threshold=1,
            recovery_timeout_seconds=10.0,
            half_open_max_probes=1
        )
        cb.record_failure(current_time=t0)
        t_recovery = t0 + timedelta(seconds=11)

        # 1 probe admitted via check_execution_allowed
        assert cb.check_execution_allowed(current_time=t_recovery) is True

        # Second concurrent probe is blocked
        with pytest.raises(CircuitBrokenError):
            cb.check_execution_allowed(current_time=t_recovery)

        # Admitted probe fails
        cb.record_failure(current_time=t_recovery)
        assert cb.get_state(current_time=t_recovery) == CircuitBreakerState.OPEN

        # All subsequent attempts fail closed
        with pytest.raises(CircuitBrokenError):
            cb.check_execution_allowed(current_time=t_recovery)

    def test_half_open_release_probe_allows_retry(self):
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        cb = CircuitBreaker(target="probe_release_test", failure_threshold=1, recovery_timeout_seconds=10.0, half_open_max_probes=1)
        cb.record_failure(current_time=t0)
        t_recovery = t0 + timedelta(seconds=11)

        assert cb.check_execution_allowed(current_time=t_recovery) is True
        with pytest.raises(CircuitBrokenError):
            cb.check_execution_allowed(current_time=t_recovery)

        # Probe is aborted without success/failure
        cb.release_probe()

        # Another probe can now be admitted
        assert cb.check_execution_allowed(current_time=t_recovery) is True


class TestCapacityGovernorAtomicity:
    """Tests for sliding-window capacity governor and atomic concurrency."""

    def test_capacity_within_limits(self):
        gov = CapacityGovernor(max_actions_per_window=5, max_volume_in_cents_per_window=50000, window_seconds=60.0)
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

        assert gov.check_capacity_available(10000, current_time=t0) is True
        gov.record_action(10000, current_time=t0)

        count, vol = gov.get_current_utilization(current_time=t0)
        assert count == 1
        assert vol == 10000

    def test_exceeding_action_count_limit_fails_closed(self):
        gov = CapacityGovernor(max_actions_per_window=2, max_volume_in_cents_per_window=100000, window_seconds=60.0)
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

        gov.record_action(100, current_time=t0)
        gov.record_action(100, current_time=t0)

        # 3rd action exceeds count limit (2)
        with pytest.raises(CapacityExceededError, match="Action rate limit exceeded"):
            gov.check_capacity_available(100, current_time=t0)

        with pytest.raises(CapacityExceededError):
            gov.record_action(100, current_time=t0)

    def test_exceeding_monetary_volume_limit_fails_closed(self):
        gov = CapacityGovernor(max_actions_per_window=10, max_volume_in_cents_per_window=25000, window_seconds=60.0)
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

        gov.record_action(20000, current_time=t0)

        # Adding 6000 would exceed volume limit of 25000
        with pytest.raises(CapacityExceededError, match="Monetary volume limit exceeded"):
            gov.check_capacity_available(6000, current_time=t0)

    def test_sliding_window_expiration_restores_capacity(self):
        gov = CapacityGovernor(max_actions_per_window=2, max_volume_in_cents_per_window=10000, window_seconds=30.0)
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

        gov.record_action(5000, current_time=t0)
        gov.record_action(5000, current_time=t0)

        # At t0 + 10s, capacity is fully utilized
        t_during = t0 + timedelta(seconds=10)
        with pytest.raises(CapacityExceededError):
            gov.check_capacity_available(100, current_time=t_during)

        # At t0 + 31s, the window expired
        t_after = t0 + timedelta(seconds=31)
        assert gov.check_capacity_available(5000, current_time=t_after) is True
        count, vol = gov.get_current_utilization(current_time=t_after)
        assert count == 0
        assert vol == 0

    def test_negative_amount_rejected(self):
        gov = CapacityGovernor()
        with pytest.raises(ValueError, match="cannot be negative"):
            gov.check_capacity_available(-500)
        with pytest.raises(ValueError, match="cannot be negative"):
            gov.record_action(-500)

    def test_concurrent_action_count_reservation_atomicity(self):
        """Proves exact count ceiling enforcement under heavy multithreaded contention."""
        gov = CapacityGovernor(max_actions_per_window=15, max_volume_in_cents_per_window=1_000_000, window_seconds=60.0)
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

        successes = []
        failures = []

        def attempt_record(task_id: int):
            try:
                gov.record_action(amount_in_cents=100, current_time=t0)
                successes.append(task_id)
            except CapacityExceededError:
                failures.append(task_id)

        with ThreadPoolExecutor(max_workers=16) as executor:
            futures = [executor.submit(attempt_record, i) for i in range(100)]
            for f in futures:
                f.result()

        # Exactly 15 succeeded, exactly 85 failed closed
        assert len(successes) == 15
        assert len(failures) == 85

        count, vol = gov.get_current_utilization(current_time=t0)
        assert count == 15
        assert vol == 1500

    def test_concurrent_monetary_volume_reservation_atomicity(self):
        """Proves exact monetary volume ceiling enforcement under heavy multithreaded contention."""
        gov = CapacityGovernor(max_actions_per_window=100, max_volume_in_cents_per_window=20000, window_seconds=60.0)
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

        successes = []
        failures = []

        def attempt_record(task_id: int):
            try:
                gov.record_action(amount_in_cents=5000, current_time=t0)
                successes.append(task_id)
            except CapacityExceededError:
                failures.append(task_id)

        with ThreadPoolExecutor(max_workers=16) as executor:
            futures = [executor.submit(attempt_record, i) for i in range(50)]
            for f in futures:
                f.result()

        # Exactly 4 operations of 5000 cents succeeded (4 * 5000 = 20000 max), 46 failed
        assert len(successes) == 4
        assert len(failures) == 46

        count, vol = gov.get_current_utilization(current_time=t0)
        assert count == 4
        assert vol == 20000


class TestGranularCircuitBreakerRegistry:
    """Tests for per-channel / per-target circuit breaker registry."""

    def test_granular_breakers_isolate_channels(self):
        registry = GranularCircuitBreakerRegistry(default_failure_threshold=2)

        # Trip DIRECT_PAYMENT_GATEWAY
        registry.record_failure(ActionChannel.DIRECT_PAYMENT_GATEWAY)
        registry.record_failure(ActionChannel.DIRECT_PAYMENT_GATEWAY)

        # Gateway channel is broken
        with pytest.raises(CircuitBrokenError):
            registry.check_execution_allowed(ActionChannel.DIRECT_PAYMENT_GATEWAY)

        # SMS channel is unaffected and allowed
        assert registry.check_execution_allowed(ActionChannel.SMS) is True
        assert registry.check_execution_allowed(ActionChannel.EMAIL) is True

    def test_reset_all_granular_breakers(self):
        registry = GranularCircuitBreakerRegistry(default_failure_threshold=1)
        registry.record_failure(ActionChannel.SMS)
        with pytest.raises(CircuitBrokenError):
            registry.check_execution_allowed(ActionChannel.SMS)

        registry.reset_all()
        assert registry.check_execution_allowed(ActionChannel.SMS) is True


class TestSafetyVerdictsAndExports:
    """Tests for safety verdicts and public symbols."""

    def test_safety_verdict_enum_values(self):
        assert SafetyVerdict.PASS == "PASS"
        assert SafetyVerdict.CIRCUIT_BROKEN == "CIRCUIT_BROKEN"
        assert SafetyVerdict.KILL_SWITCH_ACTIVE == "KILL_SWITCH_ACTIVE"
        assert SafetyVerdict.CAPACITY_EXCEEDED == "CAPACITY_EXCEEDED"

    def test_public_safety_exports_include_circuit_breaker(self):
        import src.revenue_recovery.safety as safety
        assert hasattr(safety, "CircuitBreaker")
        assert hasattr(safety, "CircuitBreakerState")
        assert hasattr(safety, "CircuitBrokenError")
        assert hasattr(safety, "GranularCircuitBreakerRegistry")
        assert hasattr(safety, "CapacityGovernor")
        assert hasattr(safety, "CapacityExceededError")
        assert hasattr(safety, "SafetyVerdict")
