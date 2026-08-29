"""Fail-closed global and granular Kill Switch implementation.

Architecture Baseline: Frozen Architecture Baseline v11.
Provides instantaneous, multi-tiered execution halting for the revenue recovery engine.
Supports global system shutdown and granular isolation (by ActionType, ActionChannel, customer_id, case_id).
"""

from datetime import datetime, timezone
from enum import Enum
import threading
from typing import Any
from pydantic import Field

from src.revenue_recovery.foundation.events import (
    ActionChannel,
    ActionType,
    ImmutableBaseModel,
)


class KillSwitchScope(str, Enum):
    """Scope tier for a kill switch activation."""
    GLOBAL = "GLOBAL"
    ACTION_TYPE = "ACTION_TYPE"
    ACTION_CHANNEL = "ACTION_CHANNEL"
    CUSTOMER = "CUSTOMER"
    CASE = "CASE"


class KillSwitchActiveError(Exception):
    """Raised when an execution attempt is blocked by an active kill switch."""

    def __init__(self, message: str, scope: KillSwitchScope | str, target: str | None, reason: str, activated_at: datetime) -> None:
        super().__init__(message)
        self.scope = KillSwitchScope(scope) if isinstance(scope, str) else scope
        self.target = target
        self.reason = reason
        self.activated_at = activated_at


class KillSwitchRecord(ImmutableBaseModel):
    """Immutable audit record representing an active kill switch trigger."""
    scope: KillSwitchScope
    target: str = Field(description="Scope target identifier (e.g. 'GLOBAL', ActionType value, customer ID, or case ID)")
    reason: str = Field(min_length=1)
    activated_by: str = Field(min_length=1)
    activated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class KillSwitchManager:
    """
    Thread-safe, fail-closed manager for global and granular kill switches.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._global_switch: KillSwitchRecord | None = None
        self._action_type_switches: dict[str, KillSwitchRecord] = {}
        self._channel_switches: dict[str, KillSwitchRecord] = {}
        self._customer_switches: dict[str, KillSwitchRecord] = {}
        self._case_switches: dict[str, KillSwitchRecord] = {}

    # --- Global Scope ---

    def activate_global(self, reason: str, activated_by: str = "system") -> KillSwitchRecord:
        """Activates the global kill switch, halting all recovery actions across the entire platform."""
        with self._lock:
            record = KillSwitchRecord(
                scope=KillSwitchScope.GLOBAL,
                target="GLOBAL",
                reason=reason.strip() if reason else "Unspecified global emergency halt",
                activated_by=activated_by
            )
            self._global_switch = record
            return record

    def deactivate_global(self) -> bool:
        """Deactivates the global kill switch."""
        with self._lock:
            if self._global_switch is not None:
                self._global_switch = None
                return True
            return False

    def is_global_active(self) -> bool:
        """Returns True if the global kill switch is currently active."""
        with self._lock:
            return self._global_switch is not None

    # --- ActionType Granular Scope ---

    def activate_action_type(self, action_type: ActionType | str, reason: str, activated_by: str = "system") -> KillSwitchRecord:
        """Activates a kill switch for a specific recovery action type (e.g. RETRY_CHARGE)."""
        key = action_type.value if isinstance(action_type, ActionType) else str(action_type)
        with self._lock:
            record = KillSwitchRecord(
                scope=KillSwitchScope.ACTION_TYPE,
                target=key,
                reason=reason.strip() if reason else f"Halted action type {key}",
                activated_by=activated_by
            )
            self._action_type_switches[key] = record
            return record

    def deactivate_action_type(self, action_type: ActionType | str) -> bool:
        """Deactivates a kill switch for a specific action type."""
        key = action_type.value if isinstance(action_type, ActionType) else str(action_type)
        with self._lock:
            return self._action_type_switches.pop(key, None) is not None

    # --- ActionChannel Granular Scope ---

    def activate_channel(self, channel: ActionChannel | str, reason: str, activated_by: str = "system") -> KillSwitchRecord:
        """Activates a kill switch for a specific communication/execution channel (e.g. DIRECT_PAYMENT_GATEWAY, SMS)."""
        key = channel.value if isinstance(channel, ActionChannel) else str(channel)
        with self._lock:
            record = KillSwitchRecord(
                scope=KillSwitchScope.ACTION_CHANNEL,
                target=key,
                reason=reason.strip() if reason else f"Halted channel {key}",
                activated_by=activated_by
            )
            self._channel_switches[key] = record
            return record

    def deactivate_channel(self, channel: ActionChannel | str) -> bool:
        """Deactivates a kill switch for a specific channel."""
        key = channel.value if isinstance(channel, ActionChannel) else str(channel)
        with self._lock:
            return self._channel_switches.pop(key, None) is not None

    # --- Customer Granular Scope ---

    def activate_customer(self, customer_id: str, reason: str, activated_by: str = "system") -> KillSwitchRecord:
        """Activates a kill switch halting all recovery execution for a specific customer."""
        cust_id = str(customer_id).strip()
        with self._lock:
            record = KillSwitchRecord(
                scope=KillSwitchScope.CUSTOMER,
                target=cust_id,
                reason=reason.strip() if reason else f"Halted customer {cust_id}",
                activated_by=activated_by
            )
            self._customer_switches[cust_id] = record
            return record

    def deactivate_customer(self, customer_id: str) -> bool:
        """Deactivates a customer-specific kill switch."""
        cust_id = str(customer_id).strip()
        with self._lock:
            return self._customer_switches.pop(cust_id, None) is not None

    # --- Case Granular Scope ---

    def activate_case(self, case_id: str, reason: str, activated_by: str = "system") -> KillSwitchRecord:
        """Activates a kill switch halting all recovery execution for a specific case."""
        c_id = str(case_id).strip()
        with self._lock:
            record = KillSwitchRecord(
                scope=KillSwitchScope.CASE,
                target=c_id,
                reason=reason.strip() if reason else f"Halted case {c_id}",
                activated_by=activated_by
            )
            self._case_switches[c_id] = record
            return record

    def deactivate_case(self, case_id: str) -> bool:
        """Deactivates a case-specific kill switch."""
        c_id = str(case_id).strip()
        with self._lock:
            return self._case_switches.pop(c_id, None) is not None

    # --- Evaluation & Fail-Closed Enforcement ---

    def get_active_switch_record(
        self,
        action_type: ActionType | str | None = None,
        channel: ActionChannel | str | None = None,
        customer_id: str | None = None,
        case_id: str | None = None
    ) -> KillSwitchRecord | None:
        """
        Evaluates active kill switches in order of precedence:
        1. GLOBAL
        2. ACTION_TYPE
        3. ACTION_CHANNEL
        4. CUSTOMER
        5. CASE
        Returns the matching KillSwitchRecord if tripped, or None if clear.
        """
        with self._lock:
            # 1. Global
            if self._global_switch is not None:
                return self._global_switch

            # 2. ActionType
            if action_type is not None:
                type_key = action_type.value if isinstance(action_type, ActionType) else str(action_type)
                if type_key in self._action_type_switches:
                    return self._action_type_switches[type_key]

            # 3. Channel
            if channel is not None:
                chan_key = channel.value if isinstance(channel, ActionChannel) else str(channel)
                if chan_key in self._channel_switches:
                    return self._channel_switches[chan_key]

            # 4. Customer
            if customer_id is not None:
                cust_key = str(customer_id).strip()
                if cust_key in self._customer_switches:
                    return self._customer_switches[cust_key]

            # 5. Case
            if case_id is not None:
                case_key = str(case_id).strip()
                if case_key in self._case_switches:
                    return self._case_switches[case_key]

            return None

    def is_active(
        self,
        action_type: ActionType | str | None = None,
        channel: ActionChannel | str | None = None,
        customer_id: str | None = None,
        case_id: str | None = None
    ) -> bool:
        """Returns True if any applicable kill switch is active for the given execution context."""
        return self.get_active_switch_record(action_type, channel, customer_id, case_id) is not None

    def check_execution_allowed(
        self,
        action_type: ActionType | str | None = None,
        channel: ActionChannel | str | None = None,
        customer_id: str | None = None,
        case_id: str | None = None
    ) -> bool:
        """
        Fail-closed execution authorization gate.
        Returns True if clear.
        Raises KillSwitchActiveError if any matching kill switch is active.
        """
        record = self.get_active_switch_record(action_type, channel, customer_id, case_id)
        if record is not None:
            scope_val = record.scope.value if hasattr(record.scope, "value") else str(record.scope)
            raise KillSwitchActiveError(
                message=f"Execution halted by {scope_val} kill switch on target '{record.target}': {record.reason}",
                scope=record.scope,
                target=record.target,
                reason=record.reason,
                activated_at=record.activated_at
            )
        return True

    def reset_all(self) -> None:
        """Deactivates all global and granular kill switches."""
        with self._lock:
            self._global_switch = None
            self._action_type_switches.clear()
            self._channel_switches.clear()
            self._customer_switches.clear()
            self._case_switches.clear()
