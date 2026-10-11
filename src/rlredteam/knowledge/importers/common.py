"""Local catalogue conversion helpers; never fetch URIs or write source files."""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

from ..models import (
    EntityType,
    KnowledgeEntity,
    KnowledgeReference,
    KnowledgeSource,
    KnowledgeStatus,
    SourceType,
)
from ..registry import KnowledgeRegistry
from ..relations import KnowledgeRelation, RelationType
from ..serialization import canonical_json
from ..validation import ModelError, text

ROOT = Path(__file__).resolve().parents[4]
IMPORTER_VERSION = "security-rl-native-import-v1"


def identifier(namespace, *keys):
    return namespace + ":" + hashlib.sha256(canonical_json(keys).encode()).hexdigest()[:32]


def source_location(path):
    try:
        return Path(path).resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return Path(path).resolve().as_uri()


class UniqueLoader(yaml.SafeLoader):
    """Reject duplicate source keys rather than silently replacing facts."""


def _mapping(loader, node):
    pairs = loader.construct_pairs(node, deep=True)
    result = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in result:
            raise ModelError("duplicate or non-string YAML key")
        result[key] = value
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def load_local(filename, path=None):
    selected = Path(path) if path is not None else ROOT / "configs/catalogues" / filename
    content = selected.read_bytes()
    if len(content) > 8 * 1024 * 1024:
        raise ModelError("catalogue exceeds 8 MiB")
    try:
        document = yaml.load(content, Loader=UniqueLoader)
    except yaml.YAMLError as exc:
        raise ModelError("invalid YAML catalogue") from exc
    if not isinstance(document, dict) or not isinstance(document.get("catalogue"), dict):
        raise ModelError("missing catalogue object")
    raw = document["catalogue"]
    text(raw.get("version"), "catalogue version")
    return raw, selected, hashlib.sha256(content).hexdigest()


class Builder:
    def __init__(self, namespace, path, checksum, version, imported_at):
        self.namespace = namespace
        location = source_location(path)
        self.source = KnowledgeSource(
            source_id=f"source:{namespace}",
            source_type=SourceType.IMPORTED_CATALOGUE,
            title=location,
            publisher="Security-RL repository",
            imported_at=imported_at,
            canonical_uri=location,
            upstream_version=version,
            content_hash=checksum,
            notes=f"Read-only local import; importer={IMPORTER_VERSION}; licence not inferred",
        )
        self._entities, self._relations, self._references = {}, {}, {}

    def ref(self, key):
        ref_id = identifier(f"{self.namespace}-ref", key)
        self._references.setdefault(
            ref_id,
            KnowledgeReference(
                reference_id=ref_id,
                source_id=self.source.source_id,
                locator=f"{self.source.canonical_uri}#{key}",
            ),
        )
        return ref_id

    def entity(self, key, kind, name, raw=None, *, synthetic=True, native_id=None):
        entity_id = identifier(self.namespace, key)
        native_id = native_id if native_id is not None else key
        entity = KnowledgeEntity(
            stable_id=entity_id,
            entity_type=kind,
            name=name,
            source_ids=(self.source.source_id,),
            reference_ids=(self.ref(key),),
            aliases=(native_id,),
            version=self.source.upstream_version,
            status=KnowledgeStatus.SYNTHETIC if synthetic else KnowledgeStatus.ACTIVE,
            attributes={"native_id": native_id, "source_record": raw or {}},
        )
        if entity_id in self._entities and self._entities[entity_id] != entity:
            raise ModelError(f"conflicting imported entity: {key}")
        self._entities[entity_id] = entity
        return entity_id

    def relation(self, source, target, kind, *, native_type=None, raw=None):
        key = identifier("rel", source, target, kind.value, native_type)
        if key in self._relations:
            raise ModelError(f"duplicate imported relation: {key}")
        self._relations[key] = KnowledgeRelation(
            relation_id=key,
            source_entity_id=source,
            target_entity_id=target,
            relation_type=kind,
            source_ids=(self.source.source_id,),
            reference_ids=(self.ref(key),),
            version=self.source.upstream_version,
            attributes={"native_type": native_type, "source_record": raw or {}},
        )

    def product(self, key, product, version, raw):
        product_id = self.entity(
            f"{key}/product",
            EntityType.SOFTWARE_PRODUCT,
            product,
            {"product": product},
            native_id=product,
        )
        version_id = self.entity(
            f"{key}/version/{version}",
            EntityType.SOFTWARE_VERSION,
            f"{product} {version}",
            raw,
            native_id=version,
        )
        self.relation(version_id, product_id, RelationType.INSTANCE_OF)
        return version_id

    def finish(self):
        return KnowledgeRegistry(
            entities=self._entities.values(),
            relations=self._relations.values(),
            sources=(self.source,),
            references=self._references.values(),
        )
