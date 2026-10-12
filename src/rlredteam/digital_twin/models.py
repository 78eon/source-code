"""Immutable engineering reconstructions, never simulator truth or policy inputs."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from rlredteam.evidence.models import AssetIdentifier, EvidenceBundle, Finding
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.snapshot import KnowledgeSnapshot

from .policy import ReconstructionPolicy

SCHEMA_VERSION = "security-rl-digital-twin-v1"


class FactStatus(StrEnum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    SYNTHETIC = "SYNTHETIC"
    CONFIRMED = "CONFIRMED"


class ResolutionDecision(StrEnum):
    MATCH = "MATCH"
    POSSIBLE_MATCH = "POSSIBLE_MATCH"
    CONFLICT = "CONFLICT"
    NO_MATCH = "NO_MATCH"
    UNRESOLVED = "UNRESOLVED"


class VersionStatus(StrEnum):
    EXACT = "exact"
    RANGE = "range"
    UNKNOWN = "unknown"
    CONFLICTING = "conflicting"


class ZoneType(StrEnum):
    NETWORK_SEGMENT = "network_segment"
    TRUST_ZONE = "trust_zone"


class TwinRelationType(StrEnum):
    LOCATED_IN = "located_in"
    HOSTS = "hosts"
    EXPOSES = "exposes"
    CONNECTS_TO = "connects_to"
    DEPENDS_ON = "depends_on"
    AUTHENTICATES_TO = "authenticates_to"
    TRUSTS = "trusts"
    PROTECTS = "protects"
    CONTAINS = "contains"
    ASSOCIATED_WITH = "associated_with"


@dataclass(frozen=True, slots=True, kw_only=True)
class TwinProvenance:
    source_ids: tuple[str, ...]
    rules: tuple[str, ...]
    confidence_calculation: Mapping[str, object]
    version: str = "reconstruction-v1"

    def __post_init__(self):
        v.validate_fields(self)
        v.ids(self, "source_ids")
        v.ids(self, "rules", required=True)
        v.text(self.version, "provenance version")
        v.attributes(self, "confidence_calculation")


@dataclass(frozen=True, slots=True, kw_only=True)
class TwinObject:
    stable_id: str
    evidence_ids: tuple[str, ...]
    status: FactStatus
    confidence: float
    provenance: TwinProvenance
    created_at: str
    knowledge_ids: tuple[str, ...] = ()
    attributes: Mapping[str, object] = field(default_factory=dict)
    updated_at: str | None = None

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.stable_id)
        v.ids(self, "evidence_ids")
        v.ids(self, "knowledge_ids")
        object.__setattr__(self, "confidence", v.bounded(self.confidence))
        v.attributes(self)
        v.time_field(self, "created_at")
        v.time_field(self, "updated_at", optional=True)
        v.time_order(self.created_at, self.updated_at)
        if self.status == FactStatus.CONFIRMED:
            if "independent-identical-observations-v1" not in self.provenance.rules:
                raise v.ModelError("confirmation requires an explicit independent-support rule")


@dataclass(frozen=True, slots=True, kw_only=True)
class TwinAsset(TwinObject):
    subject_ids: tuple[str, ...]
    identifiers: tuple[AssetIdentifier, ...]
    canonical_identifiers: tuple[AssetIdentifier, ...]
    os: str | None = None
    hostname: str | None = None
    entry_point: bool = False
    crown_jewel_candidate: bool = False

    def __post_init__(self):
        TwinObject.__post_init__(self)
        v.ids(self, "subject_ids", required=True)
        for name in ("identifiers", "canonical_identifiers"):
            values = getattr(self, name)
            if len(values) != len(set(values)):
                raise v.ModelError("duplicate asset identifier")
            object.__setattr__(
                self,
                name,
                tuple(sorted(values, key=lambda item: (item.identifier_type.value, item.value))),
            )


@dataclass(frozen=True, slots=True, kw_only=True)
class TwinService(TwinObject):
    asset_id: str
    subject_ids: tuple[str, ...]
    port: int | None = None
    protocol: str | None = None

    def __post_init__(self):
        TwinObject.__post_init__(self)
        v.ids(self, "subject_ids", required=True)
        v.stable_id(self.asset_id)
        if self.port is not None and not 0 <= self.port <= 65535:
            raise v.ModelError("invalid service port")


@dataclass(frozen=True, slots=True, kw_only=True)
class TwinSoftware(TwinObject):
    asset_id: str
    subject_ids: tuple[str, ...]
    product_id: str | None
    version_status: VersionStatus
    versions: tuple[str, ...]

    def __post_init__(self):
        TwinObject.__post_init__(self)
        v.ids(self, "subject_ids", required=True)
        v.stable_id(self.asset_id)
        if (
            self.version_status in (VersionStatus.EXACT, VersionStatus.RANGE)
            and len(self.versions) != 1
        ):
            raise v.ModelError("exact/range version requires one explicit value")
        if self.version_status == VersionStatus.UNKNOWN and self.versions:
            raise v.ModelError("unknown version cannot assert a value")


@dataclass(frozen=True, slots=True, kw_only=True)
class TwinIdentity(TwinObject):
    subject_id: str
    identity_type: str
    asset_id: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class TwinZone(TwinObject):
    zone_type: ZoneType
    name: str


@dataclass(frozen=True, slots=True, kw_only=True)
class TwinRelationship(TwinObject):
    source_id: str
    target_id: str
    relation_type: TwinRelationType


@dataclass(frozen=True, slots=True, kw_only=True)
class TwinFinding(TwinObject):
    asset_id: str
    original: Finding
    service_id: str | None = None
    software_id: str | None = None

    @property
    def applicability_status(self):
        return self.original.applicability_status


@dataclass(frozen=True, slots=True, kw_only=True)
class TwinConflict(TwinObject):
    object_ids: tuple[str, ...]
    field_name: str
    alternatives: Mapping[str, object]
    resolution_state: str = "UNRESOLVED"

    def __post_init__(self):
        TwinObject.__post_init__(self)
        v.attributes(self, "alternatives")
        if self.resolution_state != "UNRESOLVED":
            raise v.ModelError("manual conflict resolution is not implemented")


@dataclass(frozen=True, slots=True, kw_only=True)
class IdentityResolution(TwinObject):
    left_evidence_id: str
    right_evidence_id: str
    decision: ResolutionDecision


@dataclass(frozen=True, slots=True, kw_only=True)
class TwinSnapshot(TwinObject):
    schema_version: str
    policy_digest: str
    knowledge_snapshot_digest: str | None
    evidence_bundle_digest: str
    asset_count: int
    relation_count: int
    finding_count: int
    conflict_count: int
    twin_digest: str

    def __post_init__(self):
        TwinObject.__post_init__(self)
        if self.schema_version != SCHEMA_VERSION:
            raise v.ModelError("unsupported snapshot schema")
        for value in (self.policy_digest, self.evidence_bundle_digest, self.twin_digest):
            v.digest_string(value)
        if self.knowledge_snapshot_digest is not None:
            v.digest_string(self.knowledge_snapshot_digest)
        if self.stable_id != "twin-snapshot:" + self.twin_digest:
            raise v.ModelError("snapshot ID/digest mismatch")
        if min(self.asset_count, self.relation_count, self.finding_count, self.conflict_count) < 0:
            raise v.ModelError("negative snapshot counts")


@dataclass(frozen=True, slots=True, kw_only=True)
class DigitalTwin(TwinObject):
    evidence: EvidenceBundle
    knowledge: KnowledgeSnapshot
    policy: ReconstructionPolicy
    assets: tuple[TwinAsset, ...] = ()
    services: tuple[TwinService, ...] = ()
    software: tuple[TwinSoftware, ...] = ()
    identities: tuple[TwinIdentity, ...] = ()
    zones: tuple[TwinZone, ...] = ()
    relationships: tuple[TwinRelationship, ...] = ()
    findings: tuple[TwinFinding, ...] = ()
    conflicts: tuple[TwinConflict, ...] = ()
    resolutions: tuple[IdentityResolution, ...] = ()
    schema_version: str = SCHEMA_VERSION
    snapshot: TwinSnapshot | None = None

    def __post_init__(self):
        from .validation import validate_twin

        TwinObject.__post_init__(self)
        for name in (
            "assets",
            "services",
            "software",
            "identities",
            "zones",
            "relationships",
            "findings",
            "conflicts",
            "resolutions",
        ):
            object.__setattr__(
                self, name, tuple(sorted(getattr(self, name), key=lambda obj: obj.stable_id))
            )
        validate_twin(self)

    def explain_entity(self, identifier):
        from .explanation import explain

        return explain(
            self,
            identifier,
            (
                self,
                *self.assets,
                *self.services,
                *self.software,
                *self.identities,
                *self.zones,
                *self.findings,
                *self.conflicts,
            ),
        )

    def explain_relation(self, identifier):
        from .explanation import explain

        return explain(self, identifier, self.relationships)

    def explain_resolution(self, identifier):
        from .explanation import explain

        return explain(self, identifier, self.resolutions)
