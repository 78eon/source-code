"""Append-only normalized evidence storage in memory; no I/O or reconciliation."""

from typing import Protocol

from rlredteam.knowledge.serialization import digest
from rlredteam.knowledge.validation import ModelError

from .models import EvidenceBundle
from .serialization import dumps, loads


class EvidenceBundleConflictError(ModelError):
    """A bundle ID already identifies different immutable content."""


class EvidenceRepository(Protocol):
    def save(self, value: EvidenceBundle) -> None: ...
    def load(self, identifier: str) -> EvidenceBundle: ...
    def list(self) -> tuple[str, ...]: ...
    def exists(self, identifier: str) -> bool: ...


class InMemoryEvidenceRepository:
    """Store validated canonical documents, not caller-owned object references.

    Content digests are internal repository metadata: digest(canonical JSON text)
    using the existing project codec. Equal IDs/content are idempotent; different
    IDs remain separate even when their subjects or network identifiers match.
    """

    def __init__(self):
        self._documents: dict[str, str] = {}
        self._content_digests: dict[str, str] = {}

    def save(self, value: EvidenceBundle) -> None:
        if not isinstance(value, EvidenceBundle):
            raise ModelError("expected EvidenceBundle")
        document = dumps(value)
        loads(document)
        content_digest = digest(document)
        if value.bundle_id in self._documents:
            if self._documents[value.bundle_id] != document:
                raise EvidenceBundleConflictError(
                    "immutable repository ID already exists with different content: "
                    + value.bundle_id
                )
            return
        self._documents[value.bundle_id] = document
        self._content_digests[value.bundle_id] = content_digest

    def load(self, identifier: str) -> EvidenceBundle:
        return loads(self._documents[identifier])

    def list(self) -> tuple[str, ...]:
        return tuple(sorted(self._documents))

    def exists(self, identifier: str) -> bool:
        return identifier in self._documents
