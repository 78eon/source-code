"""Separate versioned codec for executable drafts; preserves legacy preview serialization."""

from dataclasses import is_dataclass

from rlredteam.enterprise.model import (
    EdgeType,
    EnterpriseEdge,
    EnterpriseNode,
    NodeType,
    TrueTopology,
    Vulnerability,
)
from rlredteam.knowledge.serialization import canonical_json, encode, load_document
from rlredteam.knowledge.validation import ModelError

from . import conversion_models as m
from .conversion import SimulationConversionPolicy
from .conversion_result import SimulationConversionResult
from .serialization import model_types as twin_types
from .simulation_draft import SimulationTopologyDraft

SCHEMA = "security-rl-simulation-conversion-json-v1"
TYPES = (
    m.SelectionSource,
    m.AssumptionType,
    m.ConversionProvenance,
    m.SimulationAssumption,
    m.SimulationEntryPoint,
    m.SimulationCrownJewel,
    m.ConversionConflict,
    m.ConversionDecision,
    m.SimulationAssetDraft,
    m.SimulationServiceDraft,
    m.SimulationRelationshipDraft,
    m.SimulationIdentityDraft,
    m.SimulationZoneDraft,
    m.SimulationVulnerabilityDraft,
    SimulationTopologyDraft,
    SimulationConversionPolicy,
    SimulationConversionResult,
    EdgeType,
    EnterpriseEdge,
    EnterpriseNode,
    NodeType,
    TrueTopology,
    Vulnerability,
)


def dumps(value):
    if type(value) not in TYPES or not is_dataclass(value):
        raise ModelError("unsupported conversion model")
    if isinstance(value, SimulationConversionResult):
        value.verify()
    if isinstance(value, SimulationTopologyDraft):
        value.__post_init__()
    return canonical_json({"schema": SCHEMA, "model": encode(value)})


def loads(text):
    value = load_document(
        text, schema=SCHEMA, allowed={**twin_types(), **{t.__name__: t for t in TYPES}}
    )
    if type(value) not in TYPES:
        raise ModelError("conversion document required")
    return value
