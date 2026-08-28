"""Unit tests for append-only cryptographic audit logger (TICKET-03).

Architecture Baseline: Frozen Architecture Baseline v11.
Enforces tamper prevention, payload immutability, tamper detection, and concurrent safety.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from src.revenue_recovery.foundation.audit import (
    GENESIS_PREVIOUS_HASH,
    AuditEntry,
    AuditIntegrityError,
    CryptographicAuditLogger,
    ImmutableDict,
    canonical_json,
    compute_entry_hash,
    freeze_payload,
)


class TestCanonicalJsonAndHashing:
    """Tests verifying deterministic canonical JSON serialization and hash generation."""

    def test_canonical_json_sorts_keys_deterministically(self):
        dict1 = {"b": 2, "a": 1, "nested": {"z": 10, "y": 20}}
        dict2 = {"nested": {"y": 20, "z": 10}, "a": 1, "b": 2}
        assert canonical_json(dict1) == canonical_json(dict2)
        assert canonical_json(dict1) == '{"a":1,"b":2,"nested":{"y":20,"z":10}}'

    def test_compute_entry_hash_is_deterministic(self):
        ts = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        payload = {"customer_id": "cust_123", "amount": 5000}
        hash1 = compute_entry_hash(0, ts, "PaymentFailed", payload, GENESIS_PREVIOUS_HASH)
        hash2 = compute_entry_hash(0, ts, "PaymentFailed", {"amount": 5000, "customer_id": "cust_123"}, GENESIS_PREVIOUS_HASH)
        assert hash1 == hash2
        assert len(hash1) == 64


class TestTamperPreventionAndImmutability:
    """Tests proving that callers cannot mutate, replace, delete, or tamper with audit entries or payloads."""

    def test_public_entries_cannot_be_appended_to(self):
        logger = CryptographicAuditLogger()
        logger.append("Evt1", {"x": 1})
        entries = logger.entries
        with pytest.raises(AttributeError):
            entries.append("malicious_entry")  # type: ignore

    def test_public_entries_cannot_replace_existing_entry(self):
        logger = CryptographicAuditLogger()
        logger.append("Evt1", {"x": 1})
        entries = logger.entries
        fake_entry = logger[0]
        with pytest.raises(TypeError):
            entries[0] = fake_entry  # type: ignore

    def test_public_entries_cannot_delete_existing_entry(self):
        logger = CryptographicAuditLogger()
        logger.append("Evt1", {"x": 1})
        entries = logger.entries
        with pytest.raises(TypeError):
            del entries[0]  # type: ignore

    def test_public_entries_cannot_be_reordered(self):
        logger = CryptographicAuditLogger()
        logger.append("Evt1", {"x": 1})
        logger.append("Evt2", {"x": 2})
        entries = logger.entries
        with pytest.raises(AttributeError):
            entries.reverse()  # type: ignore

    def test_returned_audit_entry_payload_cannot_be_mutated(self):
        logger = CryptographicAuditLogger()
        entry = logger.append("Evt1", {"customer_id": "c1", "nested": {"score": 10}})
        
        # Direct mutation of top-level key must fail
        with pytest.raises(TypeError):
            entry.payload["customer_id"] = "tampered"  # type: ignore

        # Mutation of nested dictionary must fail
        with pytest.raises(TypeError):
            entry.payload["nested"]["score"] = 999  # type: ignore

        # Adding new keys to payload must fail
        with pytest.raises(TypeError):
            entry.payload["injected"] = "malicious"  # type: ignore

        # Deleting keys from payload must fail
        with pytest.raises(TypeError):
            del entry.payload["customer_id"]  # type: ignore

    def test_input_dict_mutation_after_append_does_not_affect_stored_record(self):
        logger = CryptographicAuditLogger()
        input_data = {"key": "original_value", "nested": {"count": 1}}
        entry = logger.append("Evt1", input_data)

        # Mutate the caller's input dictionary after appending
        input_data["key"] = "tampered_afterwards"
        input_data["nested"]["count"] = 999

        # Stored audit entry payload remains untouched
        assert entry.payload["key"] == "original_value"
        assert entry.payload["nested"]["count"] == 1
        assert logger.verify_chain_integrity() is True

    def test_audit_entry_fields_cannot_be_mutated(self):
        logger = CryptographicAuditLogger()
        entry = logger.append("ImmutableCheck", {"data": 123})
        with pytest.raises(ValidationError):
            entry.sequence_number = 5  # type: ignore
        with pytest.raises(ValidationError):
            entry.entry_hash = "0" * 64  # type: ignore


class TestTamperDetection:
    """Tests proving that if corruption is injected via low-level test hooks, it is detected."""

    def test_tamper_detection_on_mutated_payload(self):
        logger = CryptographicAuditLogger()
        logger.append("Event0", {"amount": 100})
        logger.append("Event1", {"amount": 200})
        logger.append("Event2", {"amount": 300})

        # Inject a corrupted entry at sequence 1
        corrupted_entry = AuditEntry(
            entry_id=logger[1].entry_id,
            sequence_number=1,
            timestamp=logger[1].timestamp,
            event_type="Event1",
            payload={"amount": 999999},  # Tampered payload
            previous_hash=logger[1].previous_hash,
            entry_hash=logger[1].entry_hash  # Old hash (mismatch)
        )
        logger._inject_corrupted_entry_for_test(1, corrupted_entry)

        with pytest.raises(AuditIntegrityError, match="Audit payload tampering detected"):
            logger.verify_chain_integrity()

    def test_tamper_detection_on_broken_hash_pointer(self):
        logger = CryptographicAuditLogger()
        logger.append("Event0", {"val": 1})
        logger.append("Event1", {"val": 2})

        # Alter the previous_hash of entry 1
        fake_prev_hash = "f" * 64
        recomputed_hash = compute_entry_hash(
            1, logger[1].timestamp, "Event1", logger[1].payload, fake_prev_hash
        )
        tampered_entry = AuditEntry(
            entry_id=logger[1].entry_id,
            sequence_number=1,
            timestamp=logger[1].timestamp,
            event_type="Event1",
            payload=logger[1].payload,
            previous_hash=fake_prev_hash,
            entry_hash=recomputed_hash
        )
        logger._inject_corrupted_entry_for_test(1, tampered_entry)

        with pytest.raises(AuditIntegrityError, match="Audit hash-chain broken"):
            logger.verify_chain_integrity()

    def test_tamper_detection_on_out_of_order_sequence(self):
        logger = CryptographicAuditLogger()
        logger.append("Event0", {"val": 1})
        logger.append("Event1", {"val": 2})

        bad_sequence_entry = AuditEntry(
            entry_id=logger[1].entry_id,
            sequence_number=99,
            timestamp=logger[1].timestamp,
            event_type=logger[1].event_type,
            payload=logger[1].payload,
            previous_hash=logger[1].previous_hash,
            entry_hash=logger[1].entry_hash
        )
        logger._inject_corrupted_entry_for_test(1, bad_sequence_entry)

        with pytest.raises(AuditIntegrityError, match="Audit sequencing error"):
            logger.verify_chain_integrity()


class TestSequentialAndConcurrentOperations:
    """Tests for normal append and concurrent execution."""

    def test_genesis_and_sequential_hash_chain(self):
        logger = CryptographicAuditLogger()
        e0 = logger.append("EventZero", {"key": "val0"})
        e1 = logger.append("EventOne", {"key": "val1"})
        e2 = logger.append("EventTwo", {"key": "val2"})

        assert e0.sequence_number == 0
        assert e1.sequence_number == 1
        assert e2.sequence_number == 2

        assert e0.previous_hash == GENESIS_PREVIOUS_HASH
        assert e1.previous_hash == e0.entry_hash
        assert e2.previous_hash == e1.entry_hash

        assert len(logger) == 3
        assert logger.verify_chain_integrity() is True

    def test_concurrent_appends_maintain_chain_integrity(self):
        logger = CryptographicAuditLogger()
        threads = 10
        appends_per_thread = 20
        total_expected = threads * appends_per_thread

        def worker(thread_idx: int):
            for i in range(appends_per_thread):
                logger.append("ConcurrentEvent", {"thread": thread_idx, "iter": i})

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(worker, t) for t in range(threads)]
            for f in futures:
                f.result()

        assert len(logger) == total_expected
        assert len(logger.entries) == total_expected

        # Verify exact sequence numbering from 0 to total_expected - 1
        sequences = [entry.sequence_number for entry in logger.entries]
        assert sequences == list(range(total_expected))

        # Verify complete cryptographic chain integrity
        assert logger.verify_chain_integrity() is True

    def test_public_foundation_exports_for_audit(self):
        from src.revenue_recovery.foundation import (
            GENESIS_PREVIOUS_HASH as F_GENESIS,
            AuditEntry as F_AuditEntry,
            AuditIntegrityError as F_AuditIntegrityError,
            CryptographicAuditLogger as F_CryptographicAuditLogger,
            ImmutableDict as F_ImmutableDict,
            canonical_json as F_canonical_json,
            compute_entry_hash as F_compute_entry_hash,
            freeze_payload as F_freeze_payload,
        )
        assert F_GENESIS == GENESIS_PREVIOUS_HASH
        assert F_AuditEntry is AuditEntry
        assert F_AuditIntegrityError is AuditIntegrityError
        assert F_CryptographicAuditLogger is CryptographicAuditLogger
        assert F_ImmutableDict is ImmutableDict
        assert F_canonical_json is canonical_json
        assert F_compute_entry_hash is compute_entry_hash
        assert F_freeze_payload is freeze_payload
