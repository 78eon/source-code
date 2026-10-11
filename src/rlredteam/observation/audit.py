"""Immutable hash-chained structured audit, not authenticated or externally anchored."""

from collections.abc import Mapping
from dataclasses import dataclass, fields
from enum import StrEnum

from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import digest


class AuditKind(StrEnum):
    SESSION_CREATED = "SESSION_CREATED"
    SCOPE_VALIDATED = "SCOPE_VALIDATED"
    OBSERVATION_ACCEPTED = "OBSERVATION_ACCEPTED"
    OBSERVATION_REJECTED = "OBSERVATION_REJECTED"
    NORMALIZATION_APPLIED = "NORMALIZATION_APPLIED"
    CONFLICT_FOUND = "CONFLICT_FOUND"
    EVIDENCE_CREATED = "EVIDENCE_CREATED"
    SESSION_COMPLETED = "SESSION_COMPLETED"


@dataclass(frozen=True, slots=True, kw_only=True)
class AuditEvent:
    sequence: int
    session_id: str
    kind: AuditKind
    timestamp: str
    details: Mapping[str, object]
    previous_digest: str
    digest: str = ""

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.session_id)
        v.time_field(self, "timestamp")
        v.attributes(self, "details")
        v.digest_string(self.previous_digest)
        if self.sequence < 0:
            raise v.ModelError("negative audit sequence")
        actual = digest(
            {item.name: getattr(self, item.name) for item in fields(self) if item.name != "digest"}
        )
        if self.digest and self.digest != actual:
            raise v.ModelError("audit event digest mismatch")
        object.__setattr__(self, "digest", actual)


@dataclass(frozen=True, slots=True, kw_only=True)
class AuditTrail:
    session_id: str
    events: tuple[AuditEvent, ...] = ()

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.session_id)
        previous, time = "0" * 64, None
        for index, event in enumerate(self.events):
            if (
                event.sequence != index
                or event.previous_digest != previous
                or event.session_id != self.session_id
            ):
                raise v.ModelError("broken audit chain")
            v.time_order(time, event.timestamp)
            previous, time = event.digest, event.timestamp

    def append(self, kind, timestamp, **details):
        event = AuditEvent(
            sequence=len(self.events),
            session_id=self.session_id,
            kind=kind,
            timestamp=timestamp,
            details=details,
            previous_digest=self.events[-1].digest if self.events else "0" * 64,
        )
        return AuditTrail(session_id=self.session_id, events=(*self.events, event))
