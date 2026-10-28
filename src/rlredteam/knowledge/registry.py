"""Validated in-memory registry. No database, implicit merging or external queries."""

from . import validation as v
from .models import EntityType, KnowledgeEntity, KnowledgeReference, KnowledgeSource
from .relations import KnowledgeRelation, RelationType


class KnowledgeRegistry:
    def __init__(self, *, entities=(), relations=(), sources=(), references=()):
        groups = (
            (entities, KnowledgeEntity),
            (relations, KnowledgeRelation),
            (sources, KnowledgeSource),
            (references, KnowledgeReference),
        )
        materialized = []
        for values, kind in groups:
            values = tuple(values)
            if any(not isinstance(item, kind) for item in values):
                raise v.ModelError(f"expected {kind.__name__}")
            materialized.append(values)
        entities, relations, sources, references = materialized
        self._entities = v.unique(entities, "stable_id")
        self._relations = v.unique(relations, "relation_id")
        self._sources = v.unique(sources, "source_id")
        self._references = v.unique(references, "reference_id")
        for ref in references:
            v.require_refs((ref.source_id,), self._sources, "reference source")
        for item in (*entities, *relations):
            v.require_refs(item.source_ids, self._sources, "sources")
            v.require_refs(item.reference_ids, self._references, "references")
            for ref in item.reference_ids:
                v.require_refs(
                    (self._references[ref].source_id,), item.source_ids, "reference owner"
                )
        for relation in relations:
            v.require_refs(
                (relation.source_entity_id, relation.target_entity_id),
                self._entities,
                "relation endpoints",
            )

    @property
    def entities(self):
        return tuple(self._entities[key] for key in sorted(self._entities))

    @property
    def relations(self):
        return tuple(self._relations[key] for key in sorted(self._relations))

    @property
    def sources(self):
        return tuple(self._sources[key] for key in sorted(self._sources))

    @property
    def references(self):
        return tuple(self._references[key] for key in sorted(self._references))

    def get_entity(self, identifier):
        return self._entities[identifier]

    def find_by_type(self, kind):
        kind = EntityType(kind)
        return tuple(item for item in self.entities if item.entity_type == kind)

    def find_by_name(self, name):
        return tuple(item for item in self.entities if item.name.casefold() == name.casefold())

    def find_by_alias(self, alias):
        return tuple(
            item
            for item in self.entities
            if alias.casefold() in {value.casefold() for value in item.aliases}
        )

    def relations_from(self, identifier):
        return tuple(item for item in self.relations if item.source_entity_id == identifier)

    def relations_to(self, identifier):
        return tuple(item for item in self.relations if item.target_entity_id == identifier)

    def related(self, identifier, relation_type=None):
        """Outgoing neighbours only, sorted and deduplicated by stable ID."""
        kind = RelationType(relation_type) if relation_type is not None else None
        targets = {
            item.target_entity_id
            for item in self.relations_from(identifier)
            if kind is None or item.relation_type == kind
        }
        return tuple(self._entities[key] for key in sorted(targets))

    def search(self, text):
        needle = text.casefold()
        return tuple(
            item
            for item in self.entities
            if needle
            in " ".join(
                (item.stable_id, item.name, item.description, *item.aliases, *item.tags)
            ).casefold()
        )
