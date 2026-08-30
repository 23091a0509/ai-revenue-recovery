"""Mock Payment and Messaging Simulators for AI Revenue Recovery MVP.

Architecture Baseline: Frozen Architecture Baseline v11.
Implements:
- Spec §7.2: Dedicated local mock endpoints simulating 200 Success, 402 Insufficient Funds,
  504 Gateway Timeout, Card Expired, and messaging deliveries.
- Strict sandbox-only isolation with zero external network connectivity.
"""

from datetime import datetime, timezone
import threading
from typing import Any, Dict, List, Optional
import uuid

from src.revenue_recovery.foundation.events import (
    ActionChannel,
    ExecutionStatus,
    FailureReason,
    ImmutableBaseModel,
)
from src.revenue_recovery.executor.sandbox_guard import (
    SandboxGuard,
    SandboxViolationError,
)


class PaymentSimulationResult(ImmutableBaseModel):
    """Immutable response payload from the mock payment simulator."""
    status: ExecutionStatus
    http_status: int
    charge_id: Optional[str] = None
    amount_in_cents: int
    currency: str
    failure_code: Optional[str] = None
    error_message: Optional[str] = None
    simulated_at: datetime = datetime.now(timezone.utc)
    raw_response: Dict[str, Any] = {}


class MessagingSimulationResult(ImmutableBaseModel):
    """Immutable response payload from the mock messaging simulator."""
    status: ExecutionStatus
    http_status: int
    message_id: Optional[str] = None
    channel: ActionChannel
    recipient: str
    delivery_status: str
    error_message: Optional[str] = None
    simulated_at: datetime = datetime.now(timezone.utc)
    raw_response: Dict[str, Any] = {}


class MockPaymentSimulator:
    """
    Deterministic in-memory Payment Gateway Simulator for Sandbox execution.
    Supports simulated 200 Success, 402 Insufficient Funds, 402 Expired Card,
    504 Gateway Timeout, and generic declines.
    """

    def __init__(self, sandbox_guard: Optional[SandboxGuard] = None) -> None:
        self._guard = sandbox_guard or SandboxGuard()
        self._lock = threading.RLock()
        self._history: List[PaymentSimulationResult] = []
        self._scenario_overrides: Dict[str, str] = {}

    def set_scenario_override(self, invoice_id: str, scenario: str) -> None:
        """Configures a forced scenario for a specific invoice_id (e.g. 'INSUFFICIENT_FUNDS')."""
        with self._lock:
            self._scenario_overrides[invoice_id] = scenario.upper()

    def clear_scenario_overrides(self) -> None:
        with self._lock:
            self._scenario_overrides.clear()

    @property
    def history(self) -> List[PaymentSimulationResult]:
        with self._lock:
            return list(self._history)

    def simulate_charge(
        self,
        destination_url: str,
        amount_in_cents: int,
        currency: str = "INR",
        invoice_id: Optional[str] = None,
        customer_id: Optional[str] = None,
        force_scenario: Optional[str] = None,
        current_time: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Executes a simulated charge attempt against the specified sandbox endpoint.
        Validates destination URL against SandboxGuard before executing.
        """
        # Enforce sandbox URL firewall
        self._guard.check_egress_allowed(destination_url)

        now = current_time or datetime.now(timezone.utc)
        inv_id = invoice_id or "inv_default"

        with self._lock:
            scenario = force_scenario or self._scenario_overrides.get(inv_id, "SUCCESS").upper()

            if scenario == "SUCCESS":
                charge_id = f"ch_mock_{uuid.uuid4().hex[:12]}"
                res = PaymentSimulationResult(
                    status=ExecutionStatus.SUCCESS,
                    http_status=200,
                    charge_id=charge_id,
                    amount_in_cents=amount_in_cents,
                    currency=currency,
                    simulated_at=now,
                    raw_response={
                        "status": "SUCCESS",
                        "http_status": 200,
                        "charge_id": charge_id,
                        "amount_in_cents": amount_in_cents,
                        "currency": currency,
                        "invoice_id": inv_id,
                        "customer_id": customer_id or "",
                        "paid": True,
                    },
                )
            elif scenario in ("INSUFFICIENT_FUNDS", "402"):
                res = PaymentSimulationResult(
                    status=ExecutionStatus.FAILED,
                    http_status=402,
                    amount_in_cents=amount_in_cents,
                    currency=currency,
                    failure_code=FailureReason.INSUFFICIENT_FUNDS.value,
                    error_message="card_declined_insufficient_funds",
                    simulated_at=now,
                    raw_response={
                        "status": "FAILED",
                        "http_status": 402,
                        "failure_code": "INSUFFICIENT_FUNDS",
                        "error": "card_declined_insufficient_funds",
                        "invoice_id": inv_id,
                    },
                )
            elif scenario == "CARD_EXPIRED":
                res = PaymentSimulationResult(
                    status=ExecutionStatus.FAILED,
                    http_status=402,
                    amount_in_cents=amount_in_cents,
                    currency=currency,
                    failure_code=FailureReason.CARD_EXPIRED.value,
                    error_message="card_declined_expired",
                    simulated_at=now,
                    raw_response={
                        "status": "FAILED",
                        "http_status": 402,
                        "failure_code": "CARD_EXPIRED",
                        "error": "card_declined_expired",
                        "invoice_id": inv_id,
                    },
                )
            elif scenario in ("GATEWAY_TIMEOUT", "504"):
                res = PaymentSimulationResult(
                    status=ExecutionStatus.FAILED,
                    http_status=504,
                    amount_in_cents=amount_in_cents,
                    currency=currency,
                    failure_code=FailureReason.GATEWAY_TIMEOUT.value,
                    error_message="payment_gateway_timeout_504",
                    simulated_at=now,
                    raw_response={
                        "status": "FAILED",
                        "http_status": 504,
                        "failure_code": "GATEWAY_TIMEOUT",
                        "error": "payment_gateway_timeout_504",
                        "invoice_id": inv_id,
                    },
                )
            else:
                res = PaymentSimulationResult(
                    status=ExecutionStatus.FAILED,
                    http_status=400,
                    amount_in_cents=amount_in_cents,
                    currency=currency,
                    failure_code=FailureReason.GENERIC_DECLINE.value,
                    error_message=f"payment_declined_{scenario.lower()}",
                    simulated_at=now,
                    raw_response={
                        "status": "FAILED",
                        "http_status": 400,
                        "failure_code": "GENERIC_DECLINE",
                        "error": f"payment_declined_{scenario.lower()}",
                        "invoice_id": inv_id,
                    },
                )

            self._history.append(res)
            return dict(res.raw_response)


class MockMessagingSimulator:
    """
    Deterministic in-memory Multi-Channel Messaging Simulator for Sandbox execution.
    Supports EMAIL, SMS, and WHATSAPP simulation with delivery tracking and error injection.
    """

    def __init__(self, sandbox_guard: Optional[SandboxGuard] = None) -> None:
        self._guard = sandbox_guard or SandboxGuard()
        self._lock = threading.RLock()
        self._history: List[MessagingSimulationResult] = []
        self._scenario_overrides: Dict[str, str] = {}

    def set_scenario_override(self, recipient: str, scenario: str) -> None:
        """Configures a forced scenario for a specific recipient."""
        with self._lock:
            self._scenario_overrides[recipient] = scenario.upper()

    def clear_scenario_overrides(self) -> None:
        with self._lock:
            self._scenario_overrides.clear()

    @property
    def history(self) -> List[MessagingSimulationResult]:
        with self._lock:
            return list(self._history)

    def simulate_dispatch(
        self,
        channel: ActionChannel,
        destination_url: str,
        recipient: str,
        message_body: str,
        template_id: Optional[str] = None,
        force_scenario: Optional[str] = None,
        current_time: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Executes a simulated message dispatch across Email, SMS, or WhatsApp.
        Validates destination URL against SandboxGuard before executing.
        """
        # Enforce sandbox URL firewall
        self._guard.check_egress_allowed(destination_url)

        now = current_time or datetime.now(timezone.utc)

        with self._lock:
            scenario = force_scenario or self._scenario_overrides.get(recipient, "SUCCESS").upper()

            if scenario == "SUCCESS":
                msg_id = f"msg_mock_{uuid.uuid4().hex[:12]}"
                res = MessagingSimulationResult(
                    status=ExecutionStatus.SUCCESS,
                    http_status=200,
                    message_id=msg_id,
                    channel=channel,
                    recipient=recipient,
                    delivery_status="DELIVERED",
                    simulated_at=now,
                    raw_response={
                        "status": "SUCCESS",
                        "http_status": 200,
                        "message_id": msg_id,
                        "channel": str(channel),
                        "recipient": recipient,
                        "delivery_status": "DELIVERED",
                        "template_id": template_id or "",
                    },
                )
            elif scenario in ("RATE_LIMITED", "429"):
                res = MessagingSimulationResult(
                    status=ExecutionStatus.FAILED,
                    http_status=429,
                    channel=channel,
                    recipient=recipient,
                    delivery_status="REJECTED",
                    error_message="messaging_provider_rate_limit_exceeded",
                    simulated_at=now,
                    raw_response={
                        "status": "FAILED",
                        "http_status": 429,
                        "error": "messaging_provider_rate_limit_exceeded",
                        "channel": str(channel),
                        "recipient": recipient,
                    },
                )
            elif scenario in ("INVALID_RECIPIENT", "400"):
                res = MessagingSimulationResult(
                    status=ExecutionStatus.FAILED,
                    http_status=400,
                    channel=channel,
                    recipient=recipient,
                    delivery_status="BOUNCED",
                    error_message="invalid_recipient_address_or_number",
                    simulated_at=now,
                    raw_response={
                        "status": "FAILED",
                        "http_status": 400,
                        "error": "invalid_recipient_address_or_number",
                        "channel": str(channel),
                        "recipient": recipient,
                    },
                )
            elif scenario in ("GATEWAY_TIMEOUT", "504"):
                res = MessagingSimulationResult(
                    status=ExecutionStatus.FAILED,
                    http_status=504,
                    channel=channel,
                    recipient=recipient,
                    delivery_status="FAILED",
                    error_message="messaging_gateway_timeout_504",
                    simulated_at=now,
                    raw_response={
                        "status": "FAILED",
                        "http_status": 504,
                        "error": "messaging_gateway_timeout_504",
                        "channel": str(channel),
                        "recipient": recipient,
                    },
                )
            else:
                res = MessagingSimulationResult(
                    status=ExecutionStatus.FAILED,
                    http_status=500,
                    channel=channel,
                    recipient=recipient,
                    delivery_status="FAILED",
                    error_message=f"dispatch_failed_{scenario.lower()}",
                    simulated_at=now,
                    raw_response={
                        "status": "FAILED",
                        "http_status": 500,
                        "error": f"dispatch_failed_{scenario.lower()}",
                        "channel": str(channel),
                        "recipient": recipient,
                    },
                )

            self._history.append(res)
            return dict(res.raw_response)


def create_sandbox_action_handler(
    payment_simulator: Optional[MockPaymentSimulator] = None,
    messaging_simulator: Optional[MockMessagingSimulator] = None,
    sandbox_guard: Optional[SandboxGuard] = None,
) -> Any:
    """
    Factory creating a unified SandboxActionHandler dispatch callable for ActionExecutor.
    Seamlessly routes payment and communication actions to their dedicated simulators.
    """
    guard = sandbox_guard or SandboxGuard()
    pay_sim = payment_simulator or MockPaymentSimulator(sandbox_guard=guard)
    msg_sim = messaging_simulator or MockMessagingSimulator(sandbox_guard=guard)

    def _handler(channel: ActionChannel, destination_url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if channel == ActionChannel.DIRECT_PAYMENT_GATEWAY:
            return pay_sim.simulate_charge(
                destination_url=destination_url,
                amount_in_cents=payload.get("amount_in_cents", 0),
                currency=payload.get("currency", "INR"),
                invoice_id=payload.get("invoice_id"),
                customer_id=payload.get("customer_id"),
                force_scenario=payload.get("force_scenario"),
            )
        elif channel in (ActionChannel.EMAIL, ActionChannel.SMS, ActionChannel.WHATSAPP):
            return msg_sim.simulate_dispatch(
                channel=channel,
                destination_url=destination_url,
                recipient=payload.get("recipient", "customer@sandbox.internal"),
                message_body=payload.get("message_body", "Recovery notice"),
                template_id=payload.get("template_id"),
                force_scenario=payload.get("force_scenario"),
            )
        elif channel == ActionChannel.INTERNAL_SYSTEM:
            # Internal system operations execute as simulated successful internal event
            guard.check_egress_allowed(destination_url)
            return {
                "status": "SUCCESS",
                "http_status": 200,
                "channel": str(channel),
                "destination_url": destination_url,
                "payload": payload,
                "action": "INTERNAL_SYSTEM_ACK",
            }
        else:
            raise ValueError(f"Unsupported action channel for sandbox simulator: {channel}")

    return _handler
