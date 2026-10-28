"""Logical snapshot hashes exclude capture/import timestamps but include source revisions."""

from collections.abc import Mapping
from dataclasses import dataclass, replace

from rlredteam.evidence.models import Provenance
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.models import KnowledgeSource
from rlredteam.knowledge.serialization import digest

from .models import SCHEMA, VulnerabilityKnowledgeEntry
from .registry import VulnerabilityKnowledgeRegistry

IMPORTER_VERSION = "security-rl-enriched-local-v1"


def logical_digest(entries, sources):
    # Imported/retrieved timestamps describe capture, not the upstream knowledge.
    normalized_sources = tuple(
        replace(s, imported_at="2000-01-01T00:00:00Z", retrieved_at=None)
        for s in sorted(sources, key=lambda s: s.source_id)
    )
    return digest(
        (SCHEMA, tuple(sorted(entries, key=lambda e: e.vulnerability_id)), normalized_sources)
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class VulnerabilityKnowledgeSnapshot:
    snapshot_id: str
    schema_version: str
    created_at: str
    entry_count: int
    product_count: int
    source_count: int
    canonical_digest: str
    source_digests: Mapping[str, str]
    importer_version: str
    provenance: Provenance
    entries: tuple[VulnerabilityKnowledgeEntry, ...]
    sources: tuple[KnowledgeSource, ...]

    def __post_init__(self):
        v.validate_fields(self)
        v.time_field(self, "created_at")
        v.attributes(self, "source_digests")
        if self.schema_version != SCHEMA or self.importer_version != IMPORTER_VERSION:
            raise v.ModelError("unsupported snapshot schema/importer")
        registry = VulnerabilityKnowledgeRegistry(
            entries=self.entries, sources=self.sources, frozen=True
        )
        object.__setattr__(self, "entries", registry.all())
        object.__setattr__(self, "sources", registry.sources)
        expected = logical_digest(self.entries, self.sources)
        if (
            self.canonical_digest != expected
            or self.snapshot_id != "vulnerability-snapshot:" + expected
        ):
            raise v.ModelError("snapshot digest/ID mismatch")
        if (self.entry_count, self.product_count, self.source_count) != (
            len(self.entries),
            len(registry.identities.products),
            len(self.sources),
        ):
            raise v.ModelError("snapshot counts mismatch")
        if dict(self.source_digests) != {s.source_id: s.content_hash for s in self.sources}:
            raise v.ModelError("snapshot source digests mismatch")
        if self.provenance.source_ids != tuple(s.source_id for s in self.sources):
            raise v.ModelError("snapshot provenance sources mismatch")

    def registry(self):
        return VulnerabilityKnowledgeRegistry(
            entries=self.entries,
            sources=self.sources,
            frozen=True,
            input_digests=self.provenance.attributes.get("input_digests", {}),
        )


def freeze(registry, *, created_at):
    checksum = logical_digest(registry.all(), registry.sources)
    return VulnerabilityKnowledgeSnapshot(
        snapshot_id="vulnerability-snapshot:" + checksum,
        schema_version=SCHEMA,
        created_at=created_at,
        entry_count=len(registry.all()),
        product_count=len(registry.identities.products),
        source_count=len(registry.sources),
        canonical_digest=checksum,
        source_digests={s.source_id: s.content_hash for s in registry.sources},
        importer_version=IMPORTER_VERSION,
        provenance=Provenance(
            source_ids=tuple(s.source_id for s in registry.sources),
            activity="freeze-enriched-knowledge",
            version=IMPORTER_VERSION,
            attributes={"input_digests": registry.input_digests},
        ),
        entries=registry.all(),
        sources=registry.sources,
    )
