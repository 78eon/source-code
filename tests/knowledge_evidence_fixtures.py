"""Synthetic domain fixtures: no scanners, databases or policy execution."""

from rlredteam.evidence.models import (
    AssetIdentifier,
    EvidenceRecord,
    EvidenceSource,
    EvidenceStatus,
    IdentifierType,
    IdentityStatus,
    ObservedAsset,
    Provenance,
)
from rlredteam.knowledge.models import EntityType, KnowledgeEntity, KnowledgeSource, SourceType
from rlredteam.knowledge.registry import KnowledgeRegistry
from rlredteam.knowledge.relations import KnowledgeRelation, RelationType

TIME = "2026-10-08T00:00:00Z"


def source():
    return KnowledgeSource(
        source_id="source:test",
        source_type=SourceType.INTERNAL,
        title="Synthetic fixture",
        publisher="Test suite",
        imported_at=TIME,
    )


def entity(key="product:a", **kwargs):
    values = dict(
        stable_id=key,
        entity_type=EntityType.SOFTWARE_PRODUCT,
        name="Example product",
        source_ids=("source:test",),
        aliases=("Example",),
        tags=("fixture",),
    )
    values.update(kwargs)
    return KnowledgeEntity(**values)


def relation(**kwargs):
    values = dict(
        relation_id="relation:1",
        source_entity_id="product:a",
        target_entity_id="product:b",
        relation_type=RelationType.USES,
        source_ids=("source:test",),
    )
    values.update(kwargs)
    return KnowledgeRelation(**values)


def registry():
    return KnowledgeRegistry(
        entities=(entity(), entity("product:b")), relations=(relation(),), sources=(source(),)
    )


def evidence_source():
    return EvidenceSource(
        source_id="source:test",
        source_type=SourceType.MANUAL_ENTRY,
        title="Synthetic test observations",
        publisher="Test suite",
        imported_at=TIME,
    )


def record(key="evidence:1", kind=EvidenceRecord, **kwargs):
    values = dict(
        evidence_id=key,
        subject_id="asset:opaque-1",
        observation_type="fixture",
        value={"os": "unknown"},
        status=EvidenceStatus.SYNTHETIC,
        confidence=0.5,
        source_id="source:test",
        observed_at=TIME,
        imported_at=TIME,
        provenance=Provenance(source_ids=("source:test",), activity="test fixture", version="1"),
    )
    values.update(kwargs)
    return kind(**values)


def asset(key="evidence:asset", **kwargs):
    values = dict(
        identifiers=(AssetIdentifier(identifier_type=IdentifierType.IPV4, value="192.0.2.10"),),
        identity_status=IdentityStatus.EXACT,
    )
    values.update(kwargs)
    return record(key, ObservedAsset, **values)
