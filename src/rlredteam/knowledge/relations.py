"""Storage-independent semantic relationships between reference concepts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from . import validation as v


class RelationType(StrEnum):
    RUNS_ON = "RUNS_ON"
    PROVIDES = "PROVIDES"
    USES = "USES"
    HOSTS = "HOSTS"
    EXPOSES = "EXPOSES"
    DEPENDS_ON = "DEPENDS_ON"
    CONNECTS_TO = "CONNECTS_TO"
    AUTHENTICATES_TO = "AUTHENTICATES_TO"
    TRUSTS = "TRUSTS"
    PROTECTS = "PROTECTS"
    CONTAINS = "CONTAINS"
    AFFECTED_BY = "AFFECTED_BY"
    INSTANCE_OF = "INSTANCE_OF"
    PART_OF = "PART_OF"
    MAPS_TO = "MAPS_TO"
    MITIGATES = "MITIGATES"
    DETECTS = "DETECTS"
    TARGETS = "TARGETS"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    COMPATIBLE_WITH = "COMPATIBLE_WITH"


@dataclass(frozen=True, slots=True, kw_only=True)
class KnowledgeRelation:
    relation_id: str
    source_entity_id: str
    target_entity_id: str
    relation_type: RelationType
    source_ids: tuple[str, ...]
    attributes: Mapping[str, object] = field(default_factory=dict)
    reference_ids: tuple[str, ...] = ()
    confidence: float | None = None
    version: str = "1"
    valid_from: str | None = None
    valid_until: str | None = None

    def __post_init__(self):
        v.validate_fields(self)
        for name in ("relation_id", "source_entity_id", "target_entity_id"):
            v.stable_id(getattr(self, name))
        v.ids(self, "source_ids", required=True)
        v.ids(self, "reference_ids")
        v.text(self.version, "version")
        v.attributes(self)
        if self.confidence is not None:
            object.__setattr__(self, "confidence", v.bounded(self.confidence))
        v.time_field(self, "valid_from", optional=True)
        v.time_field(self, "valid_until", optional=True)
        v.time_order(self.valid_from, self.valid_until)
