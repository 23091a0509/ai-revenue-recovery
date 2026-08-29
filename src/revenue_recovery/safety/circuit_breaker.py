"""Fail-closed Circuit Breaker and Capacity Governor safety components.

Architecture Baseline: Frozen Architecture Baseline v11.
Provides automatic fault isolation via 3-state Circuit Breaker (CLOSED, OPEN, HALF_OPEN)
and sliding-window rate and volume limiting via CapacityGovernor.
"""

from collections import deque
from datetime import datetime, timedelta, timezone
from enum import Enum
import threading
from typing import Any
from pydantic import Field

from src.revenue_recovery.foundation.events import (
    ActionChannel,
    ImmutableBaseModel,
)


class CircuitBreakerState(str, Enum):
    """3-state Circuit Breaker state machine."""
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class SafetyVerdict(str, Enum):
    """Evaluation safety verdicts aligning with v11 specification."""
    PASS = "PASS"
    CIRCUIT_BROKEN = "CIRCUIT_BROKEN"
    KILL_SWITCH_ACTIVE = "KILL_SWITCH_ACTIVE"
    CAPACITY_EXCEEDED = "CAPACITY_EXCEEDED"


class CircuitBrokenError(Exception):
    """Raised when an execution attempt is blocked by an OPEN or tripped circuit breaker."""

    def __init__(self, message: str, target: str, state: CircuitBreakerState, tripped_at: datetime | None = None) -> None:
        super().__init__(message)
        self.target = target
        self.state = state
        self.tripped_at = tripped_at


class CapacityExceededError(Exception):
    """Raised when an execution attempt exceeds the allowable capacity limits."""

    def __init__(self, message: str, current_count: int, max_count: int, current_volume: int, max_volume: int) -> None:
        super().__init__(message)
        self.current_count = current_count
        self.max_count = max_count
        self.current_volume = current_volume
        self.max_volume = max_volume


class CircuitBreaker:
    """
    Thread-safe, fail-closed 3-state Circuit Breaker.
    """

    def __init__(
        self,
        target: str = "GLOBAL",
        failure_threshold: int = 3,
        recovery_timeout_seconds: float = 30.0,
        half_open_success_threshold: int = 1
    ) -> None:
        if failure_threshold <= 0:
            raise ValueError("failure_threshold must be positive")
        if recovery_timeout_seconds <= 0:
            raise ValueError("recovery_timeout_seconds must be positive")
        if half_open_success_threshold <= 0:
            raise ValueError("half_open_success_threshold must be positive")

        self.target = target
        self.failure_threshold = failure_threshold
        self.recovery_timeout_seconds = recovery_timeout_seconds
        self.half_open_success_threshold = half_open_success_threshold

        self._lock = threading.RLock()
        self._state = CircuitBreakerState.CLOSED
        self._consecutive_failures = 0
        self._half_open_successes = 0
        self._tripped_at: datetime | None = None

    @property
    def state(self) -> CircuitBreakerState:
        with self._lock:
            self._evaluate_state_transition()
            return self._state

    def get_state(self, current_time: datetime | None = None) -> CircuitBreakerState:
        """Returns the current state evaluated at the specified timestamp."""
        with self._lock:
            self._evaluate_state_transition(current_time)
            return self._state

    def _evaluate_state_transition(self, current_time: datetime | None = None) -> None:
        """Internal helper to transition from OPEN to HALF_OPEN if timeout has elapsed."""
        if self._state == CircuitBreakerState.OPEN and self._tripped_at is not None:
            now = current_time or datetime.now(timezone.utc)
            elapsed = (now - self._tripped_at).total_seconds()
            if elapsed >= self.recovery_timeout_seconds:
                self._state = CircuitBreakerState.HALF_OPEN
                self._half_open_successes = 0

    def record_success(self, current_time: datetime | None = None) -> None:
        """Records a successful operation, restoring CLOSED state if in HALF_OPEN."""
        with self._lock:
            self._evaluate_state_transition(current_time)
            if self._state == CircuitBreakerState.HALF_OPEN:
                self._half_open_successes += 1
                if self._half_open_successes >= self.half_open_success_threshold:
                    self._state = CircuitBreakerState.CLOSED
                    self._consecutive_failures = 0
                    self._half_open_successes = 0
                    self._tripped_at = None
            elif self._state == CircuitBreakerState.CLOSED:
                self._consecutive_failures = 0

    def record_failure(self, current_time: datetime | None = None) -> None:
        """Records an operation failure, immediately tripping to OPEN if thresholds are reached."""
        with self._lock:
            now = current_time or datetime.now(timezone.utc)
            self._evaluate_state_transition(now)

            if self._state == CircuitBreakerState.HALF_OPEN:
                # Any failure during trial recovery trips immediately back to OPEN
                self._state = CircuitBreakerState.OPEN
                self._tripped_at = now
                self._half_open_successes = 0
            elif self._state == CircuitBreakerState.CLOSED:
                self._consecutive_failures += 1
                if self._consecutive_failures >= self.failure_threshold:
                    self._state = CircuitBreakerState.OPEN
                    self._tripped_at = now

    def check_execution_allowed(self, current_time: datetime | None = None) -> bool:
        """
        Fail-closed check. Returns True if CLOSED or HALF_OPEN.
        Raises CircuitBrokenError if OPEN.
        """
        with self._lock:
            self._evaluate_state_transition(current_time)
            if self._state == CircuitBreakerState.OPEN:
                raise CircuitBrokenError(
                    message=f"Circuit breaker for target '{self.target}' is OPEN and blocking execution",
                    target=self.target,
                    state=self._state,
                    tripped_at=self._tripped_at
                )
            return True

    def trip_manually(self, current_time: datetime | None = None) -> None:
        """Manually trips breaker to OPEN state."""
        with self._lock:
            self._state = CircuitBreakerState.OPEN
            self._tripped_at = current_time or datetime.now(timezone.utc)

    def reset(self) -> None:
        """Resets breaker back to initial CLOSED state."""
        with self._lock:
            self._state = CircuitBreakerState.CLOSED
            self._consecutive_failures = 0
            self._half_open_successes = 0
            self._tripped_at = None


class GranularCircuitBreakerRegistry:
    """
    Thread-safe registry managing circuit breakers per action channel or target endpoint.
    """

    def __init__(
        self,
        default_failure_threshold: int = 3,
        default_recovery_timeout_seconds: float = 30.0
    ) -> None:
        self.default_failure_threshold = default_failure_threshold
        self.default_recovery_timeout_seconds = default_recovery_timeout_seconds
        self._lock = threading.RLock()
        self._breakers: dict[str, CircuitBreaker] = {}

    def get_or_create(
        self,
        target: str | ActionChannel,
        failure_threshold: int | None = None,
        recovery_timeout_seconds: float | None = None
    ) -> CircuitBreaker:
        key = target.value if isinstance(target, ActionChannel) else str(target)
        with self._lock:
            if key not in self._breakers:
                self._breakers[key] = CircuitBreaker(
                    target=key,
                    failure_threshold=failure_threshold or self.default_failure_threshold,
                    recovery_timeout_seconds=recovery_timeout_seconds or self.default_recovery_timeout_seconds
                )
            return self._breakers[key]

    def check_execution_allowed(self, target: str | ActionChannel, current_time: datetime | None = None) -> bool:
        breaker = self.get_or_create(target)
        return breaker.check_execution_allowed(current_time)

    def record_success(self, target: str | ActionChannel, current_time: datetime | None = None) -> None:
        breaker = self.get_or_create(target)
        breaker.record_success(current_time)

    def record_failure(self, target: str | ActionChannel, current_time: datetime | None = None) -> None:
        breaker = self.get_or_create(target)
        breaker.record_failure(current_time)

    def reset_all(self) -> None:
        with self._lock:
            for b in self._breakers.values():
                b.reset()


class CapacityGovernor:
    """
    Thread-safe sliding-window capacity and rate governor.
    Enforces maximum execution count and cumulative monetary volume limits over a rolling time window.
    """

    def __init__(
        self,
        max_actions_per_window: int = 100,
        max_volume_in_cents_per_window: int = 1_000_000,  # 10,000.00 currency units
        window_seconds: float = 60.0
    ) -> None:
        if max_actions_per_window <= 0:
            raise ValueError("max_actions_per_window must be positive")
        if max_volume_in_cents_per_window <= 0:
            raise ValueError("max_volume_in_cents_per_window must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self.max_actions_per_window = max_actions_per_window
        self.max_volume_in_cents_per_window = max_volume_in_cents_per_window
        self.window_seconds = window_seconds

        self._lock = threading.RLock()
        # Stores tuples of (timestamp, amount_in_cents)
        self._history: deque[tuple[datetime, int]] = deque()

    def _purge_expired(self, current_time: datetime) -> None:
        """Purges records older than current_time - window_seconds."""
        cutoff = current_time - timedelta(seconds=self.window_seconds)
        while self._history and self._history[0][0] < cutoff:
            self._history.popleft()

    def get_current_utilization(self, current_time: datetime | None = None) -> tuple[int, int]:
        """Returns (current_action_count, current_volume_in_cents) in the active rolling window."""
        with self._lock:
            now = current_time or datetime.now(timezone.utc)
            self._purge_expired(now)
            count = len(self._history)
            volume = sum(amt for _, amt in self._history)
            return count, volume

    def check_capacity_available(self, requested_amount_in_cents: int = 0, current_time: datetime | None = None) -> bool:
        """
        Fail-closed check. Returns True if allowable.
        Raises CapacityExceededError if adding the requested action would exceed count or volume bounds.
        """
        if requested_amount_in_cents < 0:
            raise ValueError("requested_amount_in_cents cannot be negative")

        with self._lock:
            now = current_time or datetime.now(timezone.utc)
            self._purge_expired(now)

            current_count = len(self._history)
            current_volume = sum(amt for _, amt in self._history)

            if current_count + 1 > self.max_actions_per_window:
                raise CapacityExceededError(
                    message=f"Action rate limit exceeded: {current_count + 1} > {self.max_actions_per_window} in {self.window_seconds}s window",
                    current_count=current_count,
                    max_count=self.max_actions_per_window,
                    current_volume=current_volume,
                    max_volume=self.max_volume_in_cents_per_window
                )

            if current_volume + requested_amount_in_cents > self.max_volume_in_cents_per_window:
                raise CapacityExceededError(
                    message=f"Monetary volume limit exceeded: {current_volume + requested_amount_in_cents} > {self.max_volume_in_cents_per_window} in {self.window_seconds}s window",
                    current_count=current_count,
                    max_count=self.max_actions_per_window,
                    current_volume=current_volume,
                    max_volume=self.max_volume_in_cents_per_window
                )

            return True

    def record_action(self, amount_in_cents: int = 0, current_time: datetime | None = None) -> None:
        """
        Reserves capacity and records an executed action.
        Fails closed by calling check_capacity_available first.
        """
        with self._lock:
            now = current_time or datetime.now(timezone.utc)
            self.check_capacity_available(amount_in_cents, now)
            self._history.append((now, amount_in_cents))

    def reset(self) -> None:
        """Clears all historical action records."""
        with self._lock:
            self._history.clear()
