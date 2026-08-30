"""Unit tests for Idempotency Subsystem (INV-16).

Architecture Baseline: Frozen Architecture Baseline v11.
Enforces:
- Unique idempotency keys across authorizations and executions.
- Idempotent replay: exact parameter matches return cached outcome without re-execution.
- Conflict rejection: reusing existing idempotency key with conflicting parameters fails closed.
- Thread-safe concurrency control preventing race-condition double execution.
"""

import concurrent.futures
from datetime import datetime, timezone
import pytest

from src.revenue_recovery.foundation.events import (
    ActionChannel,
    ActionType,
    ExecutionStatus,
)
from src.revenue_recovery.executor.idempotency import (
    ExecutionRequest,
    ExecutionResult,
    IdempotencyConflictError,
    IdempotencyStore,
)


@pytest.fixture
def store() -> IdempotencyStore:
    return IdempotencyStore()


class TestIdempotencyModelsAndMatching:
    """Verifies ExecutionRequest, ExecutionResult, and parameter matching rules."""

    def test_exact_parameter_matching_succeeds(self):
        req = ExecutionRequest(
            case_id="case_idem_1",
            customer_id="cust_idem_1",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=10000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            idempotency_key="key_exact_1",
        )

        res = ExecutionResult(
            idempotency_key="key_exact_1",
            case_id="case_idem_1",
            customer_id="cust_idem_1",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=10000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            status=ExecutionStatus.SUCCESS,
            response_payload={"charge_id": "ch_mock_1"},
        )

        assert res.matches_request(req) is True

    @pytest.mark.parametrize(
        "field_override",
        [
            {"case_id": "case_DIFFERENT"},
            {"customer_id": "cust_DIFFERENT"},
            {"action_type": ActionType.OFFER_PAYMENT_PLAN},
            {"channel": ActionChannel.SMS},
            {"amount_in_cents": 20000},
            {"currency": "USD"},
            {"destination_url": "http://localhost:8001/different_path"},
        ],
    )
    def test_mismatched_parameter_matching_fails(self, field_override: dict):
        base_req_args = {
            "case_id": "case_idem_1",
            "customer_id": "cust_idem_1",
            "action_type": ActionType.RETRY_CHARGE,
            "channel": ActionChannel.DIRECT_PAYMENT_GATEWAY,
            "amount_in_cents": 10000,
            "currency": "INR",
            "destination_url": "http://localhost:8001/charge",
            "idempotency_key": "key_conflict_1",
        }

        res = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            **base_req_args,
        )

        mismatched_req_args = {**base_req_args, **field_override}
        req_mismatched = ExecutionRequest(**mismatched_req_args)

        assert res.matches_request(req_mismatched) is False


class TestIdempotencyStoreOperations:
    """Verifies store caching, retrieval, clearing, and thread safety."""

    def test_store_record_and_get(self, store: IdempotencyStore):
        assert store.get("key_non_existent") is None

        res = ExecutionResult(
            idempotency_key="key_stored_1",
            case_id="case_100",
            customer_id="cust_100",
            action_type=ActionType.RETRY_CHARGE,
            channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
            amount_in_cents=5000,
            currency="INR",
            destination_url="http://localhost:8001/charge",
            status=ExecutionStatus.SUCCESS,
            response_payload={"charge_id": "ch_mock_stored"},
        )

        store.record(res)
        retrieved = store.get("key_stored_1")
        assert retrieved == res

        store.clear()
        assert store.get("key_stored_1") is None

    def test_concurrent_recording_maintains_thread_safety(self, store: IdempotencyStore):
        def record_item(i: int):
            res = ExecutionResult(
                idempotency_key=f"concurrent_key_{i}",
                case_id=f"case_{i}",
                customer_id=f"cust_{i}",
                action_type=ActionType.RETRY_CHARGE,
                channel=ActionChannel.DIRECT_PAYMENT_GATEWAY,
                amount_in_cents=1000 + i,
                currency="INR",
                destination_url="http://localhost:8001/charge",
                status=ExecutionStatus.SUCCESS,
            )
            store.record(res)
            return store.get(f"concurrent_key_{i}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(record_item, i) for i in range(50)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert len(results) == 50
        for i, r in enumerate(results):
            assert r is not None
            assert r.status == ExecutionStatus.SUCCESS
