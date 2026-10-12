"""Typed, evidence-linked simulation projections; never observations or research inputs."""

from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import StrEnum

from rlredteam.evidence.models import ApplicabilityStatus, Provenance
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import digest

from .models import TwinAsset, TwinFinding, TwinIdentity, TwinRelationship, TwinService, TwinZone


class SelectionSource(StrEnum):
    CONFIRMED_EVIDENCE = "CONFIRMED_EVIDENCE"
    ANALYST = "ANALYST"
    SYNTHETIC_ASSUMPTION = "SYNTHETIC_ASSUMPTION"


class AssumptionType(StrEnum):
    UNKNOWN_OS_DEFAULT = "UNKNOWN_OS_DEFAULT"
    UNKNOWN_SERVICE_VERSION = "UNKNOWN_SERVICE_VERSION"
    ENTRY_POINT_SELECTION = "ENTRY_POINT_SELECTION"
    CROWN_JEWEL_SELECTION = "CROWN_JEWEL_SELECTION"
    RELATIONSHIP_COMPLETION = "RELATIONSHIP_COMPLETION"
    VULNERABILITY_ENABLEMENT = "VULNERABILITY_ENABLEMENT"
    ACCESS_LEVEL_DEFAULT = "ACCESS_LEVEL_DEFAULT"
    SIMULATOR_REQUIRED_METADATA = "SIMULATOR_REQUIRED_METADATA"


@dataclass(frozen=True, slots=True, kw_only=True)
class ConversionProvenance:
    evidence_ids: tuple[str, ...]
    knowledge_ids: tuple[str, ...]
    rules: tuple[str, ...]
    source: str
    boundary: str = "ENGINEERING_EXTENSION"

    def __post_init__(self):
        v.validate_fields(self)
        v.ids(self, "evidence_ids")
        v.ids(self, "knowledge_ids")
        v.ids(self, "rules", required=True)
        v.text(self.source, "source")
        if self.boundary != "ENGINEERING_EXTENSION":
            raise v.ModelError("conversion is engineering-only")


@dataclass(frozen=True, slots=True, kw_only=True)
class SimulationAssumption:
    assumption_id: str
    assumption_type: AssumptionType
    subject_id: str
    field: str
    assumed_value: object
    reason: str
    required_for_simulation: bool
    source_status: str
    approved: bool
    created_at: str
    provenance: Provenance
    approved_by: str | None = None
    rejected: bool = False
    label: str = "SYNTHETIC SIMULATION ASSUMPTION"

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.assumption_id)
        v.stable_id(self.subject_id)
        v.text(self.field, "assumed field")
        v.text(self.reason, "assumption reason")
        v.text(self.source_status, "source status")
        v.time_field(self, "created_at")
        object.__setattr__(self, "assumed_value", v.frozen_json(self.assumed_value))
        if self.label != "SYNTHETIC SIMULATION ASSUMPTION":
            raise v.ModelError("synthetic label is mandatory")
        if self.approved:
            v.text(self.approved_by, "approver")
            if self.rejected:
                raise v.ModelError("rejected assumption cannot be approved")
        elif self.approved_by is not None:
            raise v.ModelError("unapproved assumption must not name an approver")


def approve_assumption(assumption, *, approved_by):
    v.text(approved_by, "approver")
    return replace(assumption, approved=True, rejected=False, approved_by=approved_by)


def reject_assumption(assumption):
    return replace(assumption, approved=False, approved_by=None, rejected=True)


@dataclass(frozen=True, slots=True, kw_only=True)
class SimulationEntryPoint:
    asset_id: str
    source: SelectionSource
    evidence_ids: tuple[str, ...]
    selection_rule: str
    provenance: ConversionProvenance
    assumption_id: str | None = None

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.asset_id)
        v.ids(self, "evidence_ids")
        v.text(self.selection_rule, "selection rule")
        if self.source == SelectionSource.SYNTHETIC_ASSUMPTION:
            v.stable_id(self.assumption_id)
        elif self.assumption_id is not None:
            raise v.ModelError("non-synthetic selection must not hide an assumption")
        if self.source == SelectionSource.CONFIRMED_EVIDENCE and not self.evidence_ids:
            raise v.ModelError("evidence-selected entry/objective requires evidence")


@dataclass(frozen=True, slots=True, kw_only=True)
class SimulationCrownJewel(SimulationEntryPoint):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class ConversionConflict:
    conflict_id: str
    twin_object_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    conflict_type: str
    severity: str
    blocking: bool
    reason: str
    provenance: ConversionProvenance

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.conflict_id)
        v.ids(self, "twin_object_ids")
        v.ids(self, "evidence_ids")
        for value in (self.conflict_type, self.severity, self.reason):
            v.text(value, "conflict detail")


@dataclass(frozen=True, slots=True, kw_only=True)
class ConversionDecision:
    event: str
    subject_id: str
    reason: str
    provenance: ConversionProvenance

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.subject_id)
        for value in (self.event, self.reason):
            v.text(value, "decision")


def simulation_id(twin_id):
    return "sim:" + digest(twin_id)


@dataclass(frozen=True, slots=True, kw_only=True)
class SimulationAssetDraft:
    original: TwinAsset
    simulation_id: str

    def __post_init__(self):
        validate_projection(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class SimulationServiceDraft:
    original: TwinService
    simulation_id: str
    product_candidates: tuple[str, ...]
    versions: tuple[str, ...]
    version_status: str
    applicability_references: tuple[str, ...]

    def __post_init__(self):
        validate_projection(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class SimulationRelationshipDraft:
    original: TwinRelationship
    simulation_id: str
    simulation_enabled: bool
    enablement_reason: str

    def __post_init__(self):
        validate_projection(self)
        v.text(self.enablement_reason, "relationship decision")


@dataclass(frozen=True, slots=True, kw_only=True)
class SimulationIdentityDraft:
    original: TwinIdentity
    simulation_id: str

    def __post_init__(self):
        validate_projection(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class SimulationZoneDraft:
    original: TwinZone
    simulation_id: str

    def __post_init__(self):
        validate_projection(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class SimulationVulnerabilityDraft:
    original: TwinFinding
    vulnerability_id: str | None
    source_finding_id: str
    applicability_status: ApplicabilityStatus
    simulation_enabled: bool
    enablement_reason: str
    assumption_id: str | None
    cvss_metadata: Mapping[str, object]
    tactic_mappings: tuple[str, ...]
    provenance: ConversionProvenance

    def __post_init__(self):
        v.validate_fields(self)
        if self.source_finding_id != self.original.stable_id:
            raise v.ModelError("finding backlink mismatch")
        if self.applicability_status != self.original.applicability_status:
            raise v.ModelError("applicability must not be promoted")
        if self.simulation_enabled and self.applicability_status in (
            ApplicabilityStatus.UNKNOWN,
            ApplicabilityStatus.NOT_APPLICABLE,
        ):
            raise v.ModelError("unknown/not-applicable finding cannot be enabled")
        v.attributes(self, "cvss_metadata")


def validate_projection(value):
    v.validate_fields(value)
    if value.simulation_id != simulation_id(value.original.stable_id):
        raise v.ModelError("simulation ID must derive from canonical twin ID")
