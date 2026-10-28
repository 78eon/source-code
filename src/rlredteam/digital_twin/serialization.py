"""Allowlisted JSON, strict schemas, validated snapshots. No arbitrary imports."""

from dataclasses import is_dataclass

from rlredteam.evidence.serialization import model_types as evidence_types
from rlredteam.knowledge.serialization import canonical_json, encode, load_document
from rlredteam.knowledge.serialization import model_types as knowledge_types
from rlredteam.knowledge.validation import ModelError

from .conversion import SimulationConversionPolicy
from .models import (
    SCHEMA_VERSION,
    DigitalTwin,
    FactStatus,
    IdentityResolution,
    ResolutionDecision,
    TwinAsset,
    TwinConflict,
    TwinFinding,
    TwinIdentity,
    TwinObject,
    TwinProvenance,
    TwinRelationship,
    TwinRelationType,
    TwinService,
    TwinSnapshot,
    TwinSoftware,
    TwinZone,
    VersionStatus,
    ZoneType,
)
from .policy import ReconstructionPolicy
from .readiness import ReadinessAssessment, ReadinessStatus, SimulationTopologyDraft

TYPES = (
    SimulationConversionPolicy,
    DigitalTwin,
    FactStatus,
    IdentityResolution,
    ResolutionDecision,
    TwinAsset,
    TwinConflict,
    TwinFinding,
    TwinIdentity,
    TwinObject,
    TwinProvenance,
    TwinRelationship,
    TwinRelationType,
    TwinService,
    TwinSnapshot,
    TwinSoftware,
    TwinZone,
    VersionStatus,
    ZoneType,
    ReconstructionPolicy,
    ReadinessAssessment,
    ReadinessStatus,
    SimulationTopologyDraft,
)


def model_types():
    return {**knowledge_types(), **evidence_types(), **{kind.__name__: kind for kind in TYPES}}


def dumps(value):
    if type(value) not in TYPES or not is_dataclass(value):
        raise ModelError("not a digital twin model")
    return canonical_json({"schema": SCHEMA_VERSION, "model": encode(value)})


def loads(text):
    result = load_document(text, schema=SCHEMA_VERSION, allowed=model_types())
    if type(result) not in TYPES:
        raise ModelError("not a digital twin model")
    return result


def migrate(payload, from_version, to_version):
    if from_version != SCHEMA_VERSION or to_version != SCHEMA_VERSION:
        raise ModelError("only current-version identity migration is supported")
    return dumps(loads(payload))
