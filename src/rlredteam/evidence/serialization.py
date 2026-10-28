"""Deterministic JSON codec for evidence models; references are validated on bundle load."""

from rlredteam.knowledge.serialization import canonical_json, encode, load_document
from rlredteam.knowledge.validation import ModelError


def model_types():
    from rlredteam.knowledge.models import SourceType
    from rlredteam.knowledge.relations import RelationType
    from rlredteam.research_boundaries import ResearchBoundary

    from .models import (
        ApplicabilityStatus,
        AssetIdentifier,
        EvidenceBundle,
        EvidenceRecord,
        EvidenceSource,
        EvidenceStatus,
        Finding,
        IdentifierType,
        IdentityStatus,
        ObservedAsset,
        ObservedIdentity,
        ObservedRelationship,
        ObservedService,
        ObservedSoftware,
        Provenance,
    )

    return {
        item.__name__: item
        for item in (
            ApplicabilityStatus,
            AssetIdentifier,
            EvidenceBundle,
            EvidenceRecord,
            EvidenceSource,
            EvidenceStatus,
            Finding,
            IdentifierType,
            IdentityStatus,
            ObservedAsset,
            ObservedIdentity,
            ObservedRelationship,
            ObservedService,
            ObservedSoftware,
            Provenance,
            SourceType,
            RelationType,
            ResearchBoundary,
        )
    }


def dumps(value):
    from dataclasses import is_dataclass

    if type(value) not in model_types().values() or not is_dataclass(value):
        raise ModelError("not an evidence model")
    return canonical_json({"schema": "security-rl-evidence-json-v1", "model": encode(value)})


def loads(text):
    return load_document(text, schema="security-rl-evidence-json-v1", allowed=model_types())
