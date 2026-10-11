"""Engineering-only persistence contracts. No DBs, files, overwrite or research imports."""

from typing import Protocol

from rlredteam.evidence.models import EvidenceBundle
from rlredteam.evidence.serialization import dumps as evidence_dumps
from rlredteam.evidence.serialization import loads as evidence_loads
from rlredteam.knowledge.validation import ModelError

from .models import DigitalTwin
from .serialization import dumps, loads


class DigitalTwinRepository(Protocol):
    def save(self, value: DigitalTwin) -> None: ...
    def load(self, identifier: str) -> DigitalTwin: ...
    def list(self) -> tuple[str, ...]: ...
    def exists(self, identifier: str) -> bool: ...


class EvidenceRepository(Protocol):
    def save(self, value: EvidenceBundle) -> None: ...
    def load(self, identifier: str) -> EvidenceBundle: ...
    def list(self) -> tuple[str, ...]: ...
    def exists(self, identifier: str) -> bool: ...


class _MemoryRepository:
    def __init__(self):
        self._documents = {}

    def _store(self, key, document):
        if key in self._documents and self._documents[key] != document:
            raise ModelError("immutable repository ID already exists with different content")
        self._documents[key] = document

    def list(self):
        return tuple(sorted(self._documents))

    def exists(self, identifier):
        return identifier in self._documents


class InMemoryDigitalTwinRepository(_MemoryRepository):
    def save(self, value):
        if not isinstance(value, DigitalTwin) or value.snapshot is None:
            raise ModelError("expected snapshotted DigitalTwin")
        document = dumps(value)
        loads(document)
        self._store(value.snapshot.stable_id, document)

    def load(self, identifier):
        return loads(self._documents[identifier])


class InMemoryEvidenceRepository(_MemoryRepository):
    def save(self, value):
        if not isinstance(value, EvidenceBundle):
            raise ModelError("expected EvidenceBundle")
        document = evidence_dumps(value)
        evidence_loads(document)
        self._store(value.bundle_id, document)

    def load(self, identifier):
        return evidence_loads(self._documents[identifier])
