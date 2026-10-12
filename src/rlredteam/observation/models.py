"""Raw input and offline session models, distinct from normalized evidence."""

from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from enum import StrEnum

from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import digest

from .protocols import Capability, LiveObservationDisabledError, ObservationMode
from .provenance import ObservationProvenance
from .scope import ObservationScope

SCHEMA_VERSION = "security-rl-observation-v1"


class SessionStatus(StrEnum):
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    ABORTED = "ABORTED"


class RawStatus(StrEnum):
    SUPPLIED = "SUPPLIED"
    SYNTHETIC = "SYNTHETIC"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True, kw_only=True)
class ObservationSession:
    session_id: str
    created_at: str
    mode: ObservationMode
    scope_id: str
    collector_version: str
    host_identity: str
    provenance: ObservationProvenance
    requested_capabilities: tuple[Capability, ...] = ()
    permitted_capabilities: tuple[Capability, ...] = ()
    started_at: str | None = None
    completed_at: str | None = None
    authorization_id: str | None = None
    evidence_count: int = 0
    status: SessionStatus = SessionStatus.CREATED
    notes: str = ""
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self):
        v.validate_fields(self)
        if self.mode == ObservationMode.LIVE_LAB and self.authorization_id is None:
            raise LiveObservationDisabledError(
                "LIVE LAB EXECUTION IS DISABLED PENDING SCOPE/ETHICS APPROVAL"
            )
        for name in ("session_id", "scope_id"):
            v.stable_id(getattr(self, name))
        for name in ("collector_version", "host_identity"):
            v.text(getattr(self, name), name)
        if self.authorization_id is not None:
            v.stable_id(self.authorization_id)
        for name in ("requested_capabilities", "permitted_capabilities"):
            object.__setattr__(self, name, tuple(sorted(set(getattr(self, name)))))
        if not set(self.permitted_capabilities) <= set(self.requested_capabilities):
            raise v.ModelError("permitted capabilities were not requested")
        if self.schema_version != SCHEMA_VERSION or self.evidence_count < 0:
            raise v.ModelError("invalid session schema/count")
        for name in ("created_at", "started_at", "completed_at"):
            v.time_field(self, name, optional=name != "created_at")
        v.time_order(self.created_at, self.started_at)
        v.time_order(self.started_at, self.completed_at)
        if self.status == SessionStatus.CREATED and (self.started_at or self.completed_at):
            raise v.ModelError("unstarted session has execution timestamps")
        if self.status != SessionStatus.CREATED and self.started_at is None:
            raise v.ModelError("started session requires started_at")
        if (self.status in (SessionStatus.COMPLETED, SessionStatus.ABORTED)) != (
            self.completed_at is not None
        ):
            raise v.ModelError("session completion status/timestamp mismatch")


@dataclass(frozen=True, slots=True, kw_only=True)
class RawObservation:
    observation_id: str
    session_id: str
    capability: Capability
    subject_hint: str
    collected_at: str
    raw_fields: Mapping[str, object]
    collector: str
    provenance: ObservationProvenance
    status: RawStatus = RawStatus.SUPPLIED

    def __post_init__(self):
        v.validate_fields(self)
        for name in ("observation_id", "session_id", "subject_hint"):
            v.stable_id(getattr(self, name))
        v.time_field(self, "collected_at")
        v.text(self.collector, "collector")
        v.attributes(self, "raw_fields")
        if self.provenance.input_digest != digest(self.raw_fields):
            raise v.ModelError("raw input digest mismatch")
        if (
            self.provenance.collector != self.collector
            or self.provenance.timestamp != self.collected_at
            or self.provenance.schema_version != SCHEMA_VERSION
        ):
            raise v.ModelError("raw provenance binding mismatch")


@dataclass(frozen=True, slots=True, kw_only=True)
class RawAddressObservation(RawObservation):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class RawServiceObservation(RawObservation):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class RawTlsObservation(RawObservation):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class RawHttpObservation(RawObservation):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class RawHostnameObservation(RawObservation):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class RawRouteObservation(RawObservation):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class RawNeighbourObservation(RawObservation):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class ObservationBundle:
    bundle_id: str
    session: ObservationSession
    scope: ObservationScope
    observations: tuple[RawObservation, ...]
    provenance: ObservationProvenance
    metadata: Mapping[str, object] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION
    digest: str = ""

    def __post_init__(self):
        from .validation import validate_bundle

        v.validate_fields(self)
        v.stable_id(self.bundle_id)
        v.attributes(self, "metadata")
        object.__setattr__(
            self,
            "observations",
            tuple(sorted(self.observations, key=lambda item: item.observation_id)),
        )
        validate_bundle(self)
        actual = digest(
            {item.name: getattr(self, item.name) for item in fields(self) if item.name != "digest"}
        )
        if self.digest and self.digest != actual:
            raise v.ModelError("observation bundle digest mismatch")
        object.__setattr__(self, "digest", actual)
