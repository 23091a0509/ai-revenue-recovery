"""Append-only cryptographic audit logger with SHA-256 hash chaining.

Architecture Baseline: Frozen Architecture Baseline v11.
Provides tamper-evident audit logging for all domain events and system transitions.
"""

from datetime import datetime, timezone
import hashlib
import json
import threading
from typing import Any
import uuid
from pydantic import Field, field_validator

from src.revenue_recovery.foundation.events import ImmutableBaseModel


# Constant for the genesis block previous hash anchor (64 zeros)
GENESIS_PREVIOUS_HASH: str = "0" * 64


class AuditIntegrityError(Exception):
    """Raised when an audit chain corruption, hash mismatch, or sequencing defect is detected."""
    pass


class AuditEntry(ImmutableBaseModel):
    """Immutable, hash-chained record of an audited domain event or action."""
    entry_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sequence_number: int = Field(ge=0, description="Monotonically increasing sequence number")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str = Field(min_length=1)
    payload: dict[str, Any]
    previous_hash: str = Field(min_length=64, max_length=64)
    entry_hash: str = Field(min_length=64, max_length=64)

    @field_validator("previous_hash", "entry_hash")
    @classmethod
    def validate_hash_format(cls, v: str) -> str:
        v_lower = v.lower()
        if len(v_lower) != 64 or not all(c in "0123456789abcdef" for c in v_lower):
            raise ValueError("Hash must be a valid 64-character lowercase hex string")
        return v_lower


def canonical_json(obj: Any) -> str:
    """Serializes an object to deterministic canonical JSON (sorted keys, compact separators)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def compute_entry_hash(
    sequence_number: int,
    timestamp: datetime,
    event_type: str,
    payload: dict[str, Any],
    previous_hash: str
) -> str:
    """
    Computes the SHA-256 digest over the canonical representation of an audit entry.
    Format: sequence_number || timestamp_iso || event_type || canonical_payload || previous_hash
    """
    timestamp_iso = timestamp.isoformat()
    canonical_payload_str = canonical_json(payload)
    digest_input = f"{sequence_number}|{timestamp_iso}|{event_type}|{canonical_payload_str}|{previous_hash}".encode("utf-8")
    return hashlib.sha256(digest_input).hexdigest()


class CryptographicAuditLogger:
    """
    Thread-safe, append-only in-memory and verifiable cryptographic audit logger.
    Maintains an unbroken SHA-256 hash chain across all recorded events.
    """

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []
        self._lock = threading.Lock()

    @property
    def entries(self) -> list[AuditEntry]:
        """Returns a copy of the recorded audit entries."""
        with self._lock:
            return list(self._entries)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def append(self, event_type: str, payload: dict[str, Any], timestamp: datetime | None = None) -> AuditEntry:
        """
        Appends a new event to the audit log with cryptographic hash linking.
        """
        with self._lock:
            sequence_number = len(self._entries)
            previous_hash = (
                self._entries[-1].entry_hash if self._entries else GENESIS_PREVIOUS_HASH
            )
            entry_timestamp = timestamp or datetime.now(timezone.utc)
            entry_hash = compute_entry_hash(
                sequence_number=sequence_number,
                timestamp=entry_timestamp,
                event_type=event_type,
                payload=payload,
                previous_hash=previous_hash
            )

            entry = AuditEntry(
                sequence_number=sequence_number,
                timestamp=entry_timestamp,
                event_type=event_type,
                payload=payload,
                previous_hash=previous_hash,
                entry_hash=entry_hash
            )
            self._entries.append(entry)
            return entry

    def verify_chain_integrity(self) -> bool:
        """
        Verifies the cryptographic integrity of the entire audit chain.
        Returns True if the chain is valid.
        Raises AuditIntegrityError if any corruption or tampering is detected.
        """
        with self._lock:
            expected_prev_hash = GENESIS_PREVIOUS_HASH
            for index, entry in enumerate(self._entries):
                # 1. Verify sequence ordering
                if entry.sequence_number != index:
                    raise AuditIntegrityError(
                        f"Audit sequencing error at index {index}: expected sequence {index}, found {entry.sequence_number}"
                    )

                # 2. Verify previous hash pointer
                if entry.previous_hash != expected_prev_hash:
                    raise AuditIntegrityError(
                        f"Audit hash-chain broken at sequence {entry.sequence_number}: "
                        f"expected previous_hash '{expected_prev_hash}', found '{entry.previous_hash}'"
                    )

                # 3. Recalculate and verify entry hash
                recalculated_hash = compute_entry_hash(
                    sequence_number=entry.sequence_number,
                    timestamp=entry.timestamp,
                    event_type=entry.event_type,
                    payload=entry.payload,
                    previous_hash=entry.previous_hash
                )
                if entry.entry_hash != recalculated_hash:
                    raise AuditIntegrityError(
                        f"Audit payload tampering detected at sequence {entry.sequence_number}: "
                        f"recorded hash '{entry.entry_hash}' does not match computed hash '{recalculated_hash}'"
                    )

                expected_prev_hash = entry.entry_hash

            return True
