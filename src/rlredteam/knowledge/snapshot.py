"""Deeply immutable, content-addressed snapshots; no implicit clock or file writes."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from . import validation as v
from .models import KnowledgeEntity, KnowledgeReference, KnowledgeSource
from .registry import KnowledgeRegistry
from .relations import KnowledgeRelation
from .serialization import digest


@dataclass(frozen=True, slots=True, kw_only=True)
class KnowledgeSnapshot:
    snapshot_id: str
    schema_version: str
    created_at: str
    entities: tuple[KnowledgeEntity, ...]
    relations: tuple[KnowledgeRelation, ...]
    sources: tuple[KnowledgeSource, ...]
    references: tuple[KnowledgeReference, ...]
    entity_count: int
    relation_count: int
    source_count: int
    canonical_digest: str
    source_digests: Mapping[str, str]
    importer_versions: Mapping[str, str]

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.snapshot_id)
        if self.schema_version != "security-rl-knowledge-snapshot-v1":
            raise v.ModelError("unsupported snapshot schema")
        v.time_field(self, "created_at")
        registry = KnowledgeRegistry(
            entities=self.entities,
            relations=self.relations,
            sources=self.sources,
            references=self.references,
        )
        for name in ("entities", "relations", "sources", "references"):
            object.__setattr__(self, name, getattr(registry, name))
        for count, values in (
            (self.entity_count, self.entities),
            (self.relation_count, self.relations),
            (self.source_count, self.sources),
        ):
            if count != len(values):
                raise v.ModelError("snapshot count mismatch")
        expected = {source.source_id: digest(source) for source in self.sources}
        if dict(self.source_digests) != expected:
            raise v.ModelError("source digest mismatch")
        for key, version in self.importer_versions.items():
            v.stable_id(key)
            v.text(version, "importer version")
        v.attributes(self, "source_digests")
        v.attributes(self, "importer_versions")
        actual = digest(self.payload())
        if self.canonical_digest != actual or self.snapshot_id != f"knowledge:{actual}":
            raise v.ModelError("snapshot digest mismatch")

    def payload(self):
        return {
            name: getattr(self, name)
            for name in (
                "schema_version",
                "created_at",
                "entities",
                "relations",
                "sources",
                "references",
                "entity_count",
                "relation_count",
                "source_count",
                "source_digests",
                "importer_versions",
            )
        }

    @classmethod
    def create(cls, registry: KnowledgeRegistry, *, created_at: str, importer_versions=None):
        payload = {
            "schema_version": "security-rl-knowledge-snapshot-v1",
            "created_at": v.timestamp(created_at),
            "entities": registry.entities,
            "relations": registry.relations,
            "sources": registry.sources,
            "references": registry.references,
            "entity_count": len(registry.entities),
            "relation_count": len(registry.relations),
            "source_count": len(registry.sources),
            "source_digests": {source.source_id: digest(source) for source in registry.sources},
            "importer_versions": importer_versions or {},
        }
        checksum = digest(payload)
        return cls(snapshot_id=f"knowledge:{checksum}", canonical_digest=checksum, **payload)
