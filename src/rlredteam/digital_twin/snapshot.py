"""Logical hashes exclude dataclass creation/update timestamps, not observation time."""

from collections.abc import Mapping
from dataclasses import fields, is_dataclass, replace
from enum import Enum

from rlredteam.knowledge.serialization import digest
from rlredteam.knowledge.snapshot import KnowledgeSnapshot

from .models import SCHEMA_VERSION, TwinSnapshot


def logical_content(value):
    if isinstance(value, Enum):
        return {"enum": type(value).__name__, "value": value.value}
    if is_dataclass(value):
        excluded = {"created_at", "updated_at", "snapshot"}
        if isinstance(value, KnowledgeSnapshot):
            # These are derived from Phase 2's timestamp-sensitive payload.
            # Keep the exact provenance digest in TwinSnapshot metadata, but
            # hash knowledge content rather than its creation-time-derived ID.
            excluded |= {"snapshot_id", "canonical_digest"}
        return {
            "type": type(value).__name__,
            "fields": {
                item.name: logical_content(getattr(value, item.name))
                for item in fields(value)
                if item.name not in excluded
            },
        }
    if isinstance(value, Mapping):
        return {key: logical_content(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return tuple(logical_content(item) for item in value)
    return value


def logical_digest(value):
    return digest(logical_content(value))


def create_snapshot(twin):
    content_digest = logical_digest(twin)
    return TwinSnapshot(
        stable_id="twin-snapshot:" + content_digest,
        schema_version=SCHEMA_VERSION,
        policy_digest=digest(twin.policy),
        knowledge_snapshot_digest=twin.knowledge.canonical_digest,
        evidence_bundle_digest=logical_digest(twin.evidence),
        asset_count=len(twin.assets),
        relation_count=len(twin.relationships),
        finding_count=len(twin.findings),
        conflict_count=len(twin.conflicts),
        twin_digest=content_digest,
        created_at=twin.created_at,
        evidence_ids=twin.evidence_ids,
        knowledge_ids=twin.knowledge_ids,
        status=twin.status,
        confidence=twin.confidence,
        provenance=twin.provenance,
    )


def freeze(twin):
    return replace(twin, snapshot=create_snapshot(twin))
