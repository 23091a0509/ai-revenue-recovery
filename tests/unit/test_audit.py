"""Unit tests for append-only cryptographic audit logger (TICKET-03).

Architecture Baseline: Frozen Architecture Baseline v11.
"""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from src.revenue_recovery.foundation.audit import (
    GENESIS_PREVIOUS_HASH,
    AuditEntry,
    AuditIntegrityError,
    CryptographicAuditLogger,
    canonical_json,
    compute_entry_hash,
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


class TestCryptographicAuditLogger:
    """Tests for the CryptographicAuditLogger append and verification engine."""

    def test_genesis_entry_creation(self):
        logger = CryptographicAuditLogger()
        entry = logger.append("SystemInitialized", {"status": "ok"})

        assert entry.sequence_number == 0
        assert entry.previous_hash == GENESIS_PREVIOUS_HASH
        assert len(entry.entry_hash) == 64
        assert len(logger) == 1
        assert logger.verify_chain_integrity() is True

    def test_unbroken_sequential_hash_chain(self):
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

        assert logger.verify_chain_integrity() is True

    def test_tamper_detection_on_mutated_payload(self):
        logger = CryptographicAuditLogger()
        logger.append("Event0", {"amount": 100})
        logger.append("Event1", {"amount": 200})
        logger.append("Event2", {"amount": 300})

        # Artificially tamper with the in-memory entry payload at sequence 1
        corrupted_entry = AuditEntry(
            entry_id=logger._entries[1].entry_id,
            sequence_number=1,
            timestamp=logger._entries[1].timestamp,
            event_type="Event1",
            payload={"amount": 999999},  # Tampered payload
            previous_hash=logger._entries[1].previous_hash,
            entry_hash=logger._entries[1].entry_hash  # Old hash (mismatch)
        )
        logger._entries[1] = corrupted_entry

        with pytest.raises(AuditIntegrityError, match="Audit payload tampering detected"):
            logger.verify_chain_integrity()

    def test_tamper_detection_on_broken_hash_pointer(self):
        logger = CryptographicAuditLogger()
        logger.append("Event0", {"val": 1})
        logger.append("Event1", {"val": 2})

        # Artificially alter the previous_hash of entry 1
        fake_prev_hash = "f" * 64
        recomputed_hash = compute_entry_hash(
            1, logger._entries[1].timestamp, "Event1", logger._entries[1].payload, fake_prev_hash
        )
        tampered_entry = AuditEntry(
            entry_id=logger._entries[1].entry_id,
            sequence_number=1,
            timestamp=logger._entries[1].timestamp,
            event_type="Event1",
            payload=logger._entries[1].payload,
            previous_hash=fake_prev_hash,
            entry_hash=recomputed_hash
        )
        logger._entries[1] = tampered_entry

        with pytest.raises(AuditIntegrityError, match="Audit hash-chain broken"):
            logger.verify_chain_integrity()

    def test_tamper_detection_on_out_of_order_sequence(self):
        logger = CryptographicAuditLogger()
        logger.append("Event0", {"val": 1})
        logger.append("Event1", {"val": 2})

        # Swap entries or change sequence
        bad_sequence_entry = AuditEntry(
            entry_id=logger._entries[1].entry_id,
            sequence_number=99,  # Bad sequence
            timestamp=logger._entries[1].timestamp,
            event_type=logger._entries[1].event_type,
            payload=logger._entries[1].payload,
            previous_hash=logger._entries[1].previous_hash,
            entry_hash=logger._entries[1].entry_hash
        )
        logger._entries[1] = bad_sequence_entry

        with pytest.raises(AuditIntegrityError, match="Audit sequencing error"):
            logger.verify_chain_integrity()

    def test_audit_entry_immutability(self):
        logger = CryptographicAuditLogger()
        entry = logger.append("ImmutableCheck", {"data": 123})
        with pytest.raises(ValidationError):
            entry.sequence_number = 5  # type: ignore

    def test_public_foundation_exports_for_audit(self):
        from src.revenue_recovery.foundation import (
            GENESIS_PREVIOUS_HASH as F_GENESIS,
            AuditEntry as F_AuditEntry,
            AuditIntegrityError as F_AuditIntegrityError,
            CryptographicAuditLogger as F_CryptographicAuditLogger,
            canonical_json as F_canonical_json,
            compute_entry_hash as F_compute_entry_hash,
        )
        assert F_GENESIS == GENESIS_PREVIOUS_HASH
        assert F_AuditEntry is AuditEntry
        assert F_AuditIntegrityError is AuditIntegrityError
        assert F_CryptographicAuditLogger is CryptographicAuditLogger
        assert F_canonical_json is canonical_json
        assert F_compute_entry_hash is compute_entry_hash
