"""Reusable concepts, not assets observed in a network or PPO knowledge."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from . import validation as v


class EntityType(StrEnum):
    DEVICE_TYPE = "DEVICE_TYPE"
    OPERATING_SYSTEM = "OPERATING_SYSTEM"
    SERVICE = "SERVICE"
    SOFTWARE_PRODUCT = "SOFTWARE_PRODUCT"
    SOFTWARE_VERSION = "SOFTWARE_VERSION"
    VULNERABILITY = "VULNERABILITY"
    WEAKNESS = "WEAKNESS"
    ATTACK_TACTIC = "ATTACK_TACTIC"
    ATTACK_TECHNIQUE = "ATTACK_TECHNIQUE"
    ATTACK_SUBTECHNIQUE = "ATTACK_SUBTECHNIQUE"
    DEFENSIVE_CONTROL = "DEFENSIVE_CONTROL"
    IDENTITY_TYPE = "IDENTITY_TYPE"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    NETWORK_ZONE = "NETWORK_ZONE"
    TOPOLOGY_FAMILY = "TOPOLOGY_FAMILY"
    TOPOLOGY_PATTERN = "TOPOLOGY_PATTERN"
    CROWN_JEWEL_TYPE = "CROWN_JEWEL_TYPE"
    MALWARE = "MALWARE"
    THREAT_ACTOR = "THREAT_ACTOR"
    CAMPAIGN = "CAMPAIGN"
    SECURITY_FRAMEWORK = "SECURITY_FRAMEWORK"
    CATALOGUE = "CATALOGUE"
    PROCEDURAL_SKILL = "PROCEDURAL_SKILL"


class SourceType(StrEnum):
    INTERNAL = "INTERNAL"
    STANDARD = "STANDARD"
    PUBLIC_DATASET = "PUBLIC_DATASET"
    RESEARCH_PAPER = "RESEARCH_PAPER"
    MANUAL_ENTRY = "MANUAL_ENTRY"
    IMPORTED_CATALOGUE = "IMPORTED_CATALOGUE"


class KnowledgeStatus(StrEnum):
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    DRAFT = "DRAFT"
    SYNTHETIC = "SYNTHETIC"


@dataclass(frozen=True, slots=True, kw_only=True)
class KnowledgeSource:
    source_id: str
    source_type: SourceType
    title: str
    publisher: str
    imported_at: str
    canonical_uri: str | None = None
    upstream_version: str | None = None
    upstream_revision: str | None = None
    content_hash: str | None = None
    licence: str | None = None
    retrieved_at: str | None = None
    notes: str = ""

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.source_id)
        v.text(self.title, "title")
        v.text(self.publisher, "publisher")
        v.time_field(self, "imported_at")
        v.time_field(self, "retrieved_at", optional=True)
        if self.content_hash is not None:
            v.digest_string(self.content_hash)
        for name in ("canonical_uri", "upstream_version", "upstream_revision", "licence"):
            if getattr(self, name) is not None:
                v.text(getattr(self, name), name)


@dataclass(frozen=True, slots=True, kw_only=True)
class KnowledgeReference:
    reference_id: str
    source_id: str
    locator: str
    title: str = ""

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.reference_id)
        v.stable_id(self.source_id)
        v.text(self.locator, "locator")


@dataclass(frozen=True, slots=True, kw_only=True)
class KnowledgeEntity:
    stable_id: str
    entity_type: EntityType
    name: str
    source_ids: tuple[str, ...]
    description: str = ""
    aliases: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    attributes: Mapping[str, object] = field(default_factory=dict)
    reference_ids: tuple[str, ...] = ()
    version: str = "1"
    status: KnowledgeStatus = KnowledgeStatus.ACTIVE
    created_at: str | None = None
    updated_at: str | None = None

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.stable_id)
        v.text(self.name, "name")
        v.text(self.version, "version")
        v.ids(self, "source_ids", required=True)
        v.ids(self, "reference_ids")
        for name in ("aliases", "tags"):
            for item in getattr(self, name):
                v.text(item, name)
            object.__setattr__(self, name, tuple(sorted(set(getattr(self, name)))))
        v.attributes(self)
        v.time_field(self, "created_at", optional=True)
        v.time_field(self, "updated_at", optional=True)
        v.time_order(self.created_at, self.updated_at)
